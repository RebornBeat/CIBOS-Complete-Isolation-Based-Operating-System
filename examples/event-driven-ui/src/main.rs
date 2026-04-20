//! Event-Driven UI — State Buffering Pattern
//!
//! This example demonstrates:
//!   - State buffering pattern (no continuous render loop)
//!   - Event-driven rendering (render only when state changes)
//!   - select! for waiting on multiple event sources
//!   - Separating state mutation from rendering
//!
//! HIP concepts illustrated:
//!   The UI lane demonstrates the correct HIP pattern for UI work:
//!   - Lane stalls waiting for input OR timer (via select!)
//!   - When an event arrives, state is updated (fast, no I/O)
//!   - Rendering only happens when state.needs_render is true
//!   - The render snapshot is isolated — no shared render state
//!
//! ANTI-PATTERN (don't do this in HIP):
//!   loop {
//!     render_everything();   // Wastes CPU, causes interference
//!     Timer::sleep(16ms).await;
//!   }
//!
//! CORRECT PATTERN (this example):
//!   loop {
//!     wait for event or tick;
//!     update state if needed;
//!     render ONLY if state changed;
//!   }
//!
//! This matters because the kernel must dispatch other containers
//! when your UI container is idle. Constant rendering prevents
//! other containers from getting dispatch time on the same core.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::{collections::BTreeMap, vec::Vec, string::String};
use cibos::{Channel, Lane, Timer, select};
use core::time::Duration;

/// A simple UI element identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct ElementId(u64);

/// State of a single UI element
#[derive(Debug, Clone)]
struct ElementState {
    label: String,
    value: u64,
    highlighted: bool,
}

/// Input event types
#[derive(Debug, Clone)]
enum InputEvent {
    ButtonClick(ElementId),
    ValueChange(ElementId, u64),
    KeyPress(char),
    Quit,
}

/// The complete UI state — owned by the UI lane exclusively
/// No shared access. No locks needed. Pure single-ownership.
struct UIState {
    elements: BTreeMap<ElementId, ElementState>,
    focused: Option<ElementId>,
    tick_count: u64,
    needs_render: bool,
}

impl UIState {
    fn new() -> Self {
        let mut elements = BTreeMap::new();

        // Initialize with some elements
        for i in 0u64..5 {
            elements.insert(ElementId(i), ElementState {
                label: alloc::format!("Button {}", i),
                value: 0,
                highlighted: false,
            });
        }

        UIState {
            elements,
            focused: None,
            tick_count: 0,
            needs_render: true, // Initial render needed
        }
    }

    /// Handle an input event — may update state
    fn handle_input(&mut self, event: InputEvent) {
        match event {
            InputEvent::ButtonClick(id) => {
                if let Some(element) = self.elements.get_mut(&id) {
                    element.value += 1;
                    element.highlighted = true;
                    log::debug!("Button {:?} clicked, value now {}", id, element.value);
                }
                self.focused = Some(id);
                self.needs_render = true; // State changed → need render
            }

            InputEvent::ValueChange(id, new_value) => {
                if let Some(element) = self.elements.get_mut(&id) {
                    element.value = new_value;
                }
                self.needs_render = true;
            }

            InputEvent::KeyPress(c) => {
                log::debug!("Key pressed: '{}'", c);
                // Some keystrokes don't change visible state
                if c == 'h' {
                    // Toggle highlight on focused element
                    if let Some(focused_id) = self.focused {
                        if let Some(element) = self.elements.get_mut(&focused_id) {
                            element.highlighted = !element.highlighted;
                            self.needs_render = true;
                        }
                    }
                }
                // No render needed for other keys in this example
            }

            InputEvent::Quit => {
                log::info!("Quit event received");
                self.needs_render = false;
            }
        }
    }

    /// Handle a timer tick — periodic background updates
    fn tick(&mut self) {
        self.tick_count += 1;

        // Periodic state update (e.g., clear highlights after 3 ticks)
        if self.tick_count % 3 == 0 {
            let mut changed = false;
            for element in self.elements.values_mut() {
                if element.highlighted {
                    element.highlighted = false;
                    changed = true;
                }
            }
            if changed {
                self.needs_render = true;
            }
        }

        // Other periodic updates don't require rendering
        // This is the key optimization: most ticks → no render
    }

    /// Create a snapshot of the current state for rendering.
    ///
    /// The snapshot is an immutable copy — the UI lane can continue
    /// processing events while the render lane works from the snapshot.
    ///
    /// In this simple example, rendering happens in the same lane.
    /// In a more complex app, you'd send the snapshot to a dedicated
    /// render lane via channel.
    fn snapshot(&self) -> RenderSnapshot {
        RenderSnapshot {
            elements: self.elements.clone(),
            focused: self.focused,
            tick_count: self.tick_count,
        }
    }
}

/// Immutable snapshot of UI state for rendering
#[derive(Clone)]
struct RenderSnapshot {
    elements: BTreeMap<ElementId, ElementState>,
    focused: Option<ElementId>,
    tick_count: u64,
}

#[cibos::main]
async fn main() {
    log::info!("=== Event-Driven UI starting ===");

    // Input channel — in real app: keyboard driver, touch driver, etc.
    // Here we simulate with a producer lane
    let (input_sender, input_receiver) = Channel::new_local(32)
        .expect("Failed to create input channel");

    // Simulate some input events
    let mut input_producer = Lane::create().expect("Failed to create input producer");
    input_producer.submit(async move {
        let events = [
            InputEvent::ButtonClick(ElementId(0)),
            InputEvent::ValueChange(ElementId(1), 42),
            InputEvent::KeyPress('h'),
            InputEvent::ButtonClick(ElementId(2)),
            InputEvent::ButtonClick(ElementId(0)),
            InputEvent::KeyPress('h'),
            InputEvent::Quit,
        ];

        for event in events {
            Timer::sleep(Duration::from_millis(50)).await;
            input_sender.send(event).await.expect("Input channel closed");
        }
        input_sender.close();
    }).expect("Failed to submit input producer");

    // Run the UI loop
    ui_loop(input_receiver).await;

    input_producer.join().await;

    log::info!("=== Event-Driven UI complete ===");
}

/// The main UI loop.
///
/// Waits for either:
///   1. An input event (from input channel)
///   2. A timer tick (16ms = ~60fps maximum rate)
///
/// For each event:
///   1. Update state (fast — no I/O)
///   2. Render ONLY if state changed
async fn ui_loop(input: Channel<InputEvent>) {
    let mut state = UIState::new();
    let mut lane = Lane::create().expect("Failed to create UI lane");

    lane.submit(async move {
        log::info!("UI loop started");

        // Initial render
        render(state.snapshot());
        state.needs_render = false;

        loop {
            // Wait for EITHER an input event OR a 16ms timer tick.
            //
            // select! is a HIP-native async primitive:
            // This lane stalls waiting for either event source.
            // When either fires, the lane resumes.
            // No busy-waiting. No polling.
            //
            // 16ms tick = up to 60fps.
            // Most ticks will NOT trigger a render (state unchanged).
            // This is much more efficient than always rendering.
            let event = select! {
                event = input.receive() => {
                    match event {
                        Some(e) => UIEvent::Input(e),
                        None => {
                            log::info!("Input channel closed — exiting UI loop");
                            break;
                        }
                    }
                },
                _ = Timer::sleep(Duration::from_millis(16)) => {
                    UIEvent::Tick
                }
            };

            match event {
                UIEvent::Input(InputEvent::Quit) => {
                    log::info!("Quit received — exiting UI loop");
                    break;
                }
                UIEvent::Input(input_event) => {
                    state.handle_input(input_event);
                }
                UIEvent::Tick => {
                    state.tick();
                }
            }

            // Render only when state actually changed
            // This is the state buffering pattern:
            // Events update state cheaply; rendering is deferred
            if state.needs_render {
                render(state.snapshot());
                state.needs_render = false;
            }
        }

        log::info!("UI loop complete after {} ticks", state.tick_count);
    }).expect("Failed to submit UI lane");

    lane.join().await;
}

/// Internal event type combining input and timer events
enum UIEvent {
    Input(InputEvent),
    Tick,
}

/// Render a snapshot of UI state.
///
/// Takes a snapshot (not a reference to state) for isolation:
/// rendering does not access or modify the live state.
fn render(snapshot: RenderSnapshot) {
    log::info!("--- Render (tick {}) ---", snapshot.tick_count);

    for (id, element) in &snapshot.elements {
        let focus_marker = if snapshot.focused == Some(*id) { "►" } else { " " };
        let highlight_marker = if element.highlighted { "*" } else { " " };
        log::info!("  {} {} {}: value={}", focus_marker, highlight_marker,
                   element.label, element.value);
    }

    log::info!("--- End Render ---");
}

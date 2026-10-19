import { EventEmitter } from "node:events";
import type { AgentEvent } from "../types.js";

// Typed thin wrapper over EventEmitter so Tom emits and Jerry subscribes with no
// stringly-typed channel names leaking into the agents.
export class Bus {
  private readonly emitter = new EventEmitter();

  emit(event: AgentEvent): void {
    this.emitter.emit("event", event);
  }

  on(handler: (event: AgentEvent) => void): void {
    this.emitter.on("event", handler);
  }
}

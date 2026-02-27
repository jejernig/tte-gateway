'use strict';

class LaneLimiter {
  constructor(lanes) {
    this.lanes = new Map();
    Object.entries(lanes).forEach(([lane, limit]) => {
      this.lanes.set(lane, { limit, active: 0, queue: [] });
    });
  }

  async run(lane, fn) {
    if (!this.lanes.has(lane)) {
      return fn();
    }
    await this.acquire(lane);
    try {
      return await fn();
    } finally {
      this.release(lane);
    }
  }

  acquire(lane) {
    const laneState = this.lanes.get(lane);
    if (!laneState) return Promise.resolve();
    if (laneState.active < laneState.limit) {
      laneState.active += 1;
      return Promise.resolve();
    }
    return new Promise((resolve) => {
      laneState.queue.push(resolve);
    });
  }

  release(lane) {
    const laneState = this.lanes.get(lane);
    if (!laneState) return;
    if (laneState.queue.length > 0) {
      const next = laneState.queue.shift();
      next();
    } else {
      laneState.active = Math.max(0, laneState.active - 1);
    }
  }
}

module.exports = {
  LaneLimiter
};

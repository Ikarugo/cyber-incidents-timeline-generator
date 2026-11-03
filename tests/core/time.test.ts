import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { formatDateTime, formatDuration, formatTime, hoursBetween, joinWallClock, momentBetween, normalizeWallClock, parseWallClock, splitWallClock } from "../../src/core/time.js";

const MOMENT = "2026-03-05T09:30:00";
const MOMENT_WITH_SECONDS = "2026-03-05T09:30:15";
const SECONDS_PER_HOUR = 3600;

describe("wall clock times", () => {
    it("drops a zone suffix instead of applying it", () => {
        assert.equal(normalizeWallClock("2026-03-05T09:30:00Z"), MOMENT);
        assert.equal(normalizeWallClock("2026-03-05T09:30:00+02:00"), MOMENT);
    });

    it("fills a missing time and missing seconds", () => {
        assert.equal(normalizeWallClock("2026-03-05"), "2026-03-05T00:00:00");
        assert.equal(normalizeWallClock("2026-03-05T09:30"), MOMENT);
    });

    it("refuses dates that do not exist", () => {
        assert.equal(normalizeWallClock("2026-02-30T10:00"), null);
        assert.equal(normalizeWallClock("yesterday"), null);
    });

    it("keeps the clock reading whatever the zone of the machine", () => {
        const parsed = parseWallClock(`${MOMENT}Z`);
        assert.equal(parsed?.getHours(), 9);
        assert.equal(parsed?.getMinutes(), 30);
    });

    it("splits and joins a moment, leaving the time out when it is not known", () => {
        const date = parseWallClock(MOMENT);
        assert.deepEqual(splitWallClock(date, false), { date: "2026-03-05", time: null });
        assert.equal(joinWallClock("2026-03-05", "09:30"), MOMENT);
        assert.equal(joinWallClock("2026-03-05", null), "2026-03-05T00:00:00");
    });

    it("carries seconds through a form and back without losing them", () => {
        const date = parseWallClock(MOMENT_WITH_SECONDS);
        assert.deepEqual(splitWallClock(date, true), { date: "2026-03-05", time: "09:30:15" });
        assert.equal(joinWallClock("2026-03-05", "09:30:15"), MOMENT_WITH_SECONDS);
        assert.equal(normalizeWallClock(joinWallClock("2026-03-05", "25:99")), null);
    });

    it("shows seconds only when they were recorded, unless the caller decides", () => {
        assert.equal(formatTime(parseWallClock(MOMENT)), "09:30");
        assert.equal(formatTime(parseWallClock(MOMENT_WITH_SECONDS)), "09:30:15");
        assert.equal(formatTime(parseWallClock(MOMENT_WITH_SECONDS), false), "09:30");
        assert.equal(formatTime(parseWallClock(MOMENT), true), "09:30:00");
        assert.equal(formatDateTime(parseWallClock(MOMENT_WITH_SECONDS)), "05 Mar 2026 09:30:15");
        assert.equal(formatTime(null), "");
    });

    it("measures hours and refuses negative spans", () => {
        const from = parseWallClock("2026-03-05T08:00");
        const to = parseWallClock("2026-03-05T11:30");
        assert.equal(hoursBetween(from, to), 3.5);
        assert.equal(hoursBetween(to, from), null);
    });

    it("finds the whole second halfway between two moments, never before the first", () => {
        const from = new Date(2026, 2, 5, 9, 30);
        assert.deepEqual(momentBetween(from, new Date(2026, 2, 5, 9, 45)), new Date(2026, 2, 5, 9, 37, 30));
        assert.deepEqual(momentBetween(from, new Date(2026, 2, 5, 9, 30, 25)), new Date(2026, 2, 5, 9, 30, 12));
        assert.deepEqual(momentBetween(from, from), from);

        const late = new Date(2026, 2, 5, 9, 30, 40);
        assert.deepEqual(momentBetween(late, new Date(2026, 2, 5, 9, 30, 41)), late);
    });

    it("formats durations at a readable unit", () => {
        assert.equal(formatDuration(0.5), "30min");
        assert.equal(formatDuration(42 / SECONDS_PER_HOUR), "42s");
        assert.equal(formatDuration(59.6 / SECONDS_PER_HOUR), "1min");
        assert.equal(formatDuration(90 / SECONDS_PER_HOUR), "2min");
        assert.equal(formatDuration(3590 / SECONDS_PER_HOUR), "1h");
        assert.equal(formatDuration(5), "5h");
        assert.equal(formatDuration(72), "3d");
        assert.equal(formatDuration(null), null);
    });
});

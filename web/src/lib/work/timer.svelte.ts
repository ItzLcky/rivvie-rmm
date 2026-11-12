/**
 * The signed-in technician's running timer, shared by the /time page and the ticket sidebar so
 * both show the same state. `now` ticks once a second while a timer runs.
 */
import { api } from '#lib/api.js';
import type { TimeEntry } from './types';

export const timer = $state<{ entry: TimeEntry | null; loaded: boolean; now: number }>({ entry: null, loaded: false, now: Date.now() });

let ticking: ReturnType<typeof setInterval> | null = null;
function tick() {
	if (timer.entry && !ticking) {
		ticking = setInterval(() => (timer.now = Date.now()), 1000);
	} else if (!timer.entry && ticking) {
		clearInterval(ticking);
		ticking = null;
	}
	timer.now = Date.now();
}

/** Seconds the running timer has been going. */
export function elapsed(): number {
	return timer.entry ? (timer.now - new Date(timer.entry.started_at).getTime()) / 1000 : 0;
}

export async function loadTimer(): Promise<void> {
	try {
		timer.entry = await api.get<TimeEntry | null>('/time/timer');
	} finally {
		timer.loaded = true;
		tick();
	}
}

export interface StartTimer {
	ticket_id?: string | null;
	client_id?: string | null;
	project_id?: string | null;
	work_type_id?: string | null;
	note?: string;
}

/** Starts a timer (the server stops a running one first). */
export async function startTimer(b: StartTimer): Promise<TimeEntry> {
	const e = await api.post<TimeEntry>('/time/timer/start', b);
	timer.entry = e;
	tick();
	return e;
}

export interface StopTimer {
	note?: string;
	work_type_id?: string | null;
	billable?: boolean;
	public?: boolean;
}

/** Stops the timer, returning the finished entry. */
export async function stopTimer(b: StopTimer = {}): Promise<TimeEntry | null> {
	const e = await api.post<TimeEntry | null>('/time/timer/stop', b);
	timer.entry = null;
	tick();
	return e;
}

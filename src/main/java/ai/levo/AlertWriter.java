package ai.levo;

import burp.IBurpExtenderCallbacks;

import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;

/**
 * Write messages to the extension's Output and Errors tabs.
 */
public class AlertWriter {

    static final long RATE_LIMIT_WINDOW_MS = 30_000L;

    /**
     * Ref on Burp tool to have access to the extension's Output and Errors tabs.
     */
    private final IBurpExtenderCallbacks callbacks;

    private final LongSupplier clock;

    private final ConcurrentHashMap<String, RateLimitState> rateLimits = new ConcurrentHashMap<>();

    /**
     * Constructor.
     *
     * @param callbacks Ref on Burp tool to have access to the extension's Output and Errors tabs.
     */
    public AlertWriter(IBurpExtenderCallbacks callbacks) {
        this(callbacks, System::currentTimeMillis);
    }

    AlertWriter(IBurpExtenderCallbacks callbacks, LongSupplier clock) {
        this.callbacks = callbacks;
        this.clock = clock;
    }

    /**
     * Write an info message to the extension's Output tab.
     *
     * @param message Message to write.
     */
    public void writeInfo(String message) {
        this.callbacks.printOutput(message);
    }

    /**
     * Write an info message at most once per key per {@link #RATE_LIMIT_WINDOW_MS}.
     * Repeats in the window are counted; the next emitted line includes how many were suppressed.
     *
     * @param key     Rate-limit bucket (e.g. a normalized content-type).
     * @param message Message to write when the window allows it.
     */
    public void writeInfoRateLimited(String key, String message) {
        writeRateLimited(key, message, false);
    }

    /**
     * Write an error message to the extension's Errors tab.
     *
     * @param message Error message to write.
     */
    public void writeError(String message) {
        this.callbacks.printError(message);
    }

    /**
     * Write an error message at most once per key per {@link #RATE_LIMIT_WINDOW_MS}.
     * Repeats in the window are counted; the next emitted line includes how many were suppressed.
     *
     * @param key     Rate-limit bucket (e.g. HTTP status code of a failed satellite send).
     * @param message Message to write when the window allows it.
     */
    public void writeErrorRateLimited(String key, String message) {
        writeRateLimited(key, message, true);
    }

    private void writeRateLimited(String key, String message, boolean error) {
        String bucket = key == null ? "" : key;
        long now = this.clock.getAsLong();
        RateLimitState state = this.rateLimits.computeIfAbsent(bucket, ignored -> new RateLimitState());
        synchronized (state) {
            boolean windowExpired = state.hasLogged && (now - state.lastLoggedAtMs >= RATE_LIMIT_WINDOW_MS);
            if (!state.hasLogged || windowExpired) {
                String output = message;
                if (state.suppressedCount > 0) {
                    output = message + " (" + state.suppressedCount + " similar messages suppressed)";
                }
                if (error) {
                    this.callbacks.printError(output);
                } else {
                    this.callbacks.printOutput(output);
                }
                state.hasLogged = true;
                state.lastLoggedAtMs = now;
                state.suppressedCount = 0;
            } else {
                state.suppressedCount++;
            }
        }
    }

    private static final class RateLimitState {
        private boolean hasLogged;
        private long lastLoggedAtMs;
        private int suppressedCount;
    }
}

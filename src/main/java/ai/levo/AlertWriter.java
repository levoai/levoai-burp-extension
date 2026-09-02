package ai.levo;

import burp.IBurpExtenderCallbacks;

/**
 * Write messages to the extension's Output and Errors tabs.
 */
public class AlertWriter {

    /**
     * Ref on Burp tool to have access to the extension's Output and Errors tabs.
     */
    private final IBurpExtenderCallbacks callbacks;

    /**
     * Constructor.
     *
     * @param callbacks Ref on Burp tool to have access to the extension's Output and Errors tabs.
     */
    public AlertWriter(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
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
     * Write an error message to the extension's Errors tab.
     *
     * @param message Error message to write.
     */
    public void writeError(String message) {
        this.callbacks.printError(message);
    }
}

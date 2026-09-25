package ai.levo;

import burp.IBurpExtenderCallbacks;
import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IExtensionStateListener;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;

import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

/**
 * Adds "Send to Levo.ai" to Burp's message context menu.
 * A selected message is sent only when both content types are supported.
 */
public class SendToLevoMenu implements IContextMenuFactory, IExtensionStateListener {

    static final String MENU_LABEL = "Send to Levo.ai";
    static final String STILL_SENDING_MESSAGE =
            "Levo is still sending the messages you selected earlier.\n\nWait for that to finish, then try again.";
    private static final int MAX_REJECTION_LINES = 12;
    private static final int MAX_URL_LENGTH = 120;

    private final IBurpExtenderCallbacks callbacks;
    private final HttpMessagePublisher publisher;
    private final Executor sendExecutor;

    public SendToLevoMenu(IBurpExtenderCallbacks callbacks, HttpMessagePublisher publisher) {
        this(callbacks, publisher, defaultExecutor());
    }

    SendToLevoMenu(IBurpExtenderCallbacks callbacks, HttpMessagePublisher publisher, Executor sendExecutor) {
        this.callbacks = callbacks;
        this.publisher = publisher;
        this.sendExecutor = sendExecutor;
    }

    private static Executor defaultExecutor() {
        return new ThreadPoolExecutor(
                1, 1,
                0L, TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(1),
                r -> {
                    Thread thread = new Thread(r, "levo-send-to-levo");
                    thread.setDaemon(true);
                    return thread;
                },
                new ThreadPoolExecutor.AbortPolicy());
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        IHttpRequestResponse[] selected = invocation.getSelectedMessages();
        if (selected == null || selected.length == 0) {
            return null;
        }
        IHttpRequestResponse[] messages = Arrays.copyOf(selected, selected.length);
        JMenuItem item = new JMenuItem(MENU_LABEL);
        item.addActionListener(event -> submitSend(messages, this::notifyOnEdt));
        return Collections.singletonList(item);
    }

    /**
     * Parsing and base64 expansion run on {@link #sendExecutor}, not on Swing's event thread.
     * The executor holds one running batch and one waiting batch; a further click is told to wait.
     */
    void submitSend(IHttpRequestResponse[] messages, Consumer<String> notify) {
        try {
            sendExecutor.execute(() -> sendSelected(messages, notify));
        } catch (RejectedExecutionException ex) {
            notify.accept(STILL_SENDING_MESSAGE);
        }
    }

    void sendSelected(IHttpRequestResponse[] messages) {
        sendSelected(messages, this::notifyOnEdt);
    }

    void sendSelected(IHttpRequestResponse[] messages, Consumer<String> notify) {
        if (!ConfigMenu.IS_SENDING_ENABLED) {
            notify.accept("Sending to Levo is turned off.\n\n"
                    + "Enable Levo.ai → Send traffic to Levo, then try again.");
            return;
        }

        List<String> contentTypeRejections = new ArrayList<>();
        List<String> otherRejections = new ArrayList<>();
        int sent = 0;
        for (IHttpRequestResponse message : messages) {
            if (message == null || message.getRequest() == null || message.getResponse() == null) {
                otherRejections.add("One selected message has no response to send.");
                continue;
            }
            try {
                IRequestInfo requestInfo = callbacks.getHelpers().analyzeRequest(message);
                IResponseInfo responseInfo = callbacks.getHelpers().analyzeResponse(message.getResponse());
                String requestType = contentType(requestInfo.getHeaders());
                String responseType = contentType(responseInfo.getHeaders());
                String rejection = contentTypeRejection(
                        requestInfo.getMethod(),
                        requestInfo.getUrl().toString(),
                        requestType,
                        responseType);
                if (rejection != null) {
                    contentTypeRejections.add(rejection);
                    continue;
                }
                publisher.sendHttpMessage(
                        requestInfo,
                        message.getRequest(),
                        String.valueOf(responseInfo.getStatusCode()),
                        message.getResponse(),
                        responseInfo);
                sent++;
            } catch (RuntimeException e) {
                otherRejections.add("Could not read one selected message: " + e.getMessage());
            }
        }

        String notice = notificationText(contentTypeRejections, otherRejections, sent);
        if (notice != null) {
            notify.accept(notice);
        }
    }

    private void notifyOnEdt(String message) {
        if (SwingUtilities.isEventDispatchThread()) {
            showNotification(message);
        } else {
            SwingUtilities.invokeLater(() -> showNotification(message));
        }
    }

    private void showNotification(String message) {
        JOptionPane.showMessageDialog(
                ConfigMenu.getBurpFrame(), message, "Levo.ai", JOptionPane.INFORMATION_MESSAGE);
    }

    @Override
    public void extensionUnloaded() {
        if (sendExecutor instanceof ExecutorService) {
            ((ExecutorService) sendExecutor).shutdownNow();
        }
    }

    /**
     * @return a one-line reason when either content type is unsupported, otherwise null
     */
    static String contentTypeRejection(String method, String url, String requestContentType, String responseContentType) {
        boolean requestDropped = HttpMessagePublisher.shouldDropContentType(requestContentType);
        boolean responseDropped = HttpMessagePublisher.shouldDropContentType(responseContentType);
        if (!requestDropped && !responseDropped) {
            return null;
        }
        StringBuilder line = new StringBuilder();
        line.append(method).append(' ').append(shorten(url)).append(" — ");
        if (requestDropped) {
            line.append("request content-type '").append(display(requestContentType)).append("' is not supported");
        }
        if (responseDropped) {
            if (requestDropped) {
                line.append("; ");
            }
            line.append("response content-type '").append(display(responseContentType)).append("' is not supported");
        }
        return line.toString();
    }

    static String notificationText(List<String> contentTypeRejections, List<String> otherRejections, int sent) {
        int skipped = contentTypeRejections.size() + otherRejections.size();
        if (skipped == 0) {
            return null;
        }
        StringBuilder text = new StringBuilder();
        if (!contentTypeRejections.isEmpty() && otherRejections.isEmpty()) {
            text.append(skipped == 1
                    ? "Not sending this message because its content type is not supported."
                    : "Not sending " + skipped + " messages because their content type is not supported.");
        } else {
            text.append(skipped == 1 ? "Not sending this message." : "Not sending " + skipped + " messages.");
        }
        text.append("\n\n");
        int shown = 0;
        shown = appendLines(text, contentTypeRejections, shown);
        shown = appendLines(text, otherRejections, shown);
        int hidden = skipped - shown;
        if (hidden > 0) {
            text.append("and ").append(hidden).append(" more.\n");
        }
        if (sent > 0) {
            text.append('\n').append("Queued ").append(sent)
                    .append(sent == 1 ? " other message." : " other messages.");
        }
        return text.toString().stripTrailing();
    }

    private static int appendLines(StringBuilder text, List<String> lines, int shown) {
        for (String line : lines) {
            if (shown >= MAX_REJECTION_LINES) {
                return shown;
            }
            text.append(line).append('\n');
            shown++;
        }
        return shown;
    }

    static String contentType(List<String> headers) {
        if (headers == null) {
            return null;
        }
        String value = null;
        for (String header : headers) {
            int colon = header.indexOf(':');
            if (colon <= 0) {
                continue;
            }
            if (header.substring(0, colon).trim().equalsIgnoreCase("content-type")) {
                value = header.substring(colon + 1).trim();
            }
        }
        return value;
    }

    private static String display(String contentType) {
        if (contentType == null || contentType.isBlank()) {
            return "(missing)";
        }
        return contentType;
    }

    private static String shorten(String url) {
        if (url == null) {
            return "";
        }
        if (url.length() <= MAX_URL_LENGTH) {
            return url;
        }
        return url.substring(0, MAX_URL_LENGTH - 3) + "...";
    }
}

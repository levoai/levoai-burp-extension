package ai.levo;

import ai.levo.exceptions.SatelliteMessageFailed;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class LevoSatelliteService {

    public static LevoSatelliteService create(String satelliteUrl, IBurpExtenderCallbacks callbacks) throws MalformedURLException {
        return new LevoSatelliteService(callbacks, satelliteUrl);
    }

    private final IExtensionHelpers helpers;
    private final IBurpExtenderCallbacks callbacks;

    private final IHttpService service;

    public LevoSatelliteService(IBurpExtenderCallbacks callbacks, String satelliteUrl) throws MalformedURLException {
        this.helpers = callbacks.getHelpers();
        this.callbacks = callbacks;
        var url = new URL(satelliteUrl);
        this.service = helpers.buildHttpService(url.getHost(), url.getPort(), url.getProtocol().equals("https"));
    }

    public IHttpRequestResponse sendHttpMessage(HttpMessage httpMessage) throws SatelliteMessageFailed, JsonProcessingException {
        var mapper = new ObjectMapper();
        var jsonBody = mapper.writeValueAsString(httpMessage);
        byte[] body = helpers.stringToBytes(jsonBody);
        List<String> newHeaders = new ArrayList<>();
        newHeaders.add("POST /1.0/ebpf/traces HTTP/1.1");
        var message = helpers.buildHttpMessage(newHeaders, body);
        var requestResponse = this.callbacks.makeHttpRequest(service, message, false);

        var response = requestResponse.getResponse();
        var responseInfo = helpers.analyzeResponse(response);

        if (responseInfo.getStatusCode() >= 400) {
            int len = response.length - responseInfo.getBodyOffset();
            var result = new byte[len];
            System.arraycopy(response, responseInfo.getBodyOffset(), result, 0, len);
            throw new SatelliteMessageFailed(new String(result), responseInfo.getStatusCode());
        }

        return requestResponse;
    }
}

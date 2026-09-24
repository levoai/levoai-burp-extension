package ai.levo;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HttpMessagePublisherContentTypeTest {

    @Test
    void acceptsMixedCaseJsonAndCharsetParameter() {
        assertFalse(HttpMessagePublisher.shouldDropContentType("Application/JSON"));
        assertFalse(HttpMessagePublisher.shouldDropContentType("application/json; charset=UTF-8"));
        assertFalse(HttpMessagePublisher.shouldDropContentType("Text/Plain; charset=utf-8"));
    }

    @Test
    void acceptsXmlSoapGrpcGraphqlAndJsonApiTypes() {
        List<String> accepted = List.of(
                "application/xml",
                "text/xml",
                "Text/XML; charset=utf-8",
                "application/soap+xml",
                "application/soap+xml; charset=utf-8",
                "application/grpc",
                "application/grpc+proto",
                "application/grpc-web",
                "application/grpc-web+proto",
                "application/grpc-web-text",
                "application/grpc-web-text+proto",
                "Application/gRPC-Web+Proto",
                "application/problem+json",
                "application/vnd.api+json",
                "application/hal+json",
                "application/ld+json",
                "application/scim+json",
                "application/merge-patch+json",
                "application/graphql",
                "application/graphql+json",
                "application/graphql-response+json",
                "application/vnd.graphql+json",
                "Application/GraphQL; charset=UTF-8"
        );
        for (String contentType : accepted) {
            assertFalse(HttpMessagePublisher.shouldDropContentType(contentType), contentType);
        }
    }

    @Test
    void dropsHtmlMultipartAndUnrelatedTypes() {
        assertTrue(HttpMessagePublisher.shouldDropContentType("text/html"));
        assertTrue(HttpMessagePublisher.shouldDropContentType("text/html; charset=UTF-8"));
        assertTrue(HttpMessagePublisher.shouldDropContentType("multipart/form-data; boundary=abc"));
        assertTrue(HttpMessagePublisher.shouldDropContentType("application/javascript"));
        assertTrue(HttpMessagePublisher.shouldDropContentType("application/octet-stream"));
        assertTrue(HttpMessagePublisher.shouldDropContentType("application/xhtml+xml"));
        assertTrue(HttpMessagePublisher.shouldDropContentType(""));
        assertTrue(HttpMessagePublisher.shouldDropContentType("   "));
    }

    @Test
    void missingContentTypeIsKept() {
        assertFalse(HttpMessagePublisher.shouldDropContentType(null));
    }
}

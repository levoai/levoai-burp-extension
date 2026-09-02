package ai.levo;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;

class OrganizationIdTest {

    private static final String VALID = "123e4567-e89b-12d3-a456-426614174000";

    @Test
    void acceptsCanonicalUuid() {
        assertTrue(OrganizationId.isValid(VALID));
        assertEquals(VALID, OrganizationId.requireValid(VALID));
    }

    @Test
    void acceptsUppercaseAndTrimsWhitespaceToCanonicalForm() {
        assertEquals(VALID, OrganizationId.requireValid("  " + VALID.toUpperCase() + "\t"));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {
            "   ",
            "not-a-uuid",
            "123e4567e89b12d3a456426614174000",
            "1-1-1-1-1",
            "{123e4567-e89b-12d3-a456-426614174000}",
            "urn:uuid:123e4567-e89b-12d3-a456-426614174000",
            "123e4567-e89b-12d3-a456-426614174000-extra",
            "123e4567-e89b-12d3-a456"
    })
    void rejectsInvalidValues(String value) {
        assertFalse(OrganizationId.isValid(value));
        IllegalArgumentException thrown = assertThrows(
                IllegalArgumentException.class, () -> OrganizationId.requireValid(value));
        assertTrue(thrown.getMessage().contains("must be a UUID"));
    }

    @Test
    void validationMessageDoesNotEchoHugeInput() {
        String huge = "x".repeat(200);
        String message = OrganizationId.validationMessage(huge);
        assertTrue(message.contains("Got: '"));
        assertTrue(message.contains("..."));
        assertFalse(message.contains(huge));
    }
}

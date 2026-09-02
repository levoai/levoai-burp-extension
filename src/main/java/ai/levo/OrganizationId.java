package ai.levo;

import java.util.UUID;

/**
 * Levo organization IDs are UUIDs. Reject anything else before it is saved or sent.
 */
final class OrganizationId {

    private OrganizationId() {
    }

    static String normalize(String organizationId) {
        if (organizationId == null) {
            return null;
        }
        String trimmed = organizationId.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    static boolean isValid(String organizationId) {
        String normalized = normalize(organizationId);
        if (normalized == null) {
            return false;
        }
        try {
            UUID parsed = UUID.fromString(normalized);
            return parsed.toString().equalsIgnoreCase(normalized);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    static String requireValid(String organizationId) {
        String normalized = normalize(organizationId);
        if (!isValid(normalized)) {
            throw new IllegalArgumentException(validationMessage(organizationId));
        }
        return UUID.fromString(normalized).toString();
    }

    static String validationMessage(String organizationId) {
        String got = display(organizationId);
        return "Organization ID must be a UUID (8-4-4-4-12 hexadecimal), for example "
                + "123e4567-e89b-12d3-a456-426614174000. Got: " + got;
    }

    private static String display(String organizationId) {
        if (organizationId == null) {
            return "(missing)";
        }
        String trimmed = organizationId.trim();
        if (trimmed.isEmpty()) {
            return "(empty)";
        }
        if (trimmed.length() > 64) {
            return "'" + trimmed.substring(0, 64) + "...'";
        }
        return "'" + trimmed + "'";
    }
}

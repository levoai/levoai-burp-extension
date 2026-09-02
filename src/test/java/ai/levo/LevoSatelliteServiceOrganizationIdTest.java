package ai.levo;

import ai.levo.exceptions.SatelliteMessageFailed;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class LevoSatelliteServiceOrganizationIdTest {

    private static final String VALID = "123e4567-e89b-12d3-a456-426614174000";

    @Mock
    private IBurpExtenderCallbacks callbacks;

    @Mock
    private IExtensionHelpers helpers;

    @Mock
    private IHttpService httpService;

    @BeforeEach
    void setUp() {
        when(callbacks.getHelpers()).thenReturn(helpers);
        when(helpers.buildHttpService(anyString(), anyInt(), anyBoolean())).thenReturn(httpService);
    }

    @Test
    void updateOrganizationId_rejectsInvalidUuid() throws Exception {
        LevoSatelliteService service = newService(null);

        IllegalArgumentException thrown = assertThrows(
                IllegalArgumentException.class, () -> service.updateOrganizationId("not-a-uuid"));
        assertTrue(thrown.getMessage().contains("must be a UUID"));
    }

    @Test
    void updateOrganizationId_acceptsCanonicalUuid() throws Exception {
        LevoSatelliteService service = newService(null);
        assertDoesNotThrow(() -> service.updateOrganizationId(VALID));
    }

    @Test
    void sendHttpMessage_rejectsMissingOrganizationId() throws Exception {
        LevoSatelliteService service = newService(null);

        SatelliteMessageFailed thrown = assertThrows(
                SatelliteMessageFailed.class, () -> service.sendHttpMessage(new HttpMessage()));
        assertEquals("Organization ID is not set", thrown.getMessage());
        assertEquals((short) 400, thrown.getStatusCode());
    }

    @Test
    void sendHttpMessage_rejectsLegacyNonUuidOrganizationId() throws Exception {
        LevoSatelliteService service = newService("legacy-org-name");

        SatelliteMessageFailed thrown = assertThrows(
                SatelliteMessageFailed.class, () -> service.sendHttpMessage(new HttpMessage()));
        assertTrue(thrown.getMessage().contains("must be a UUID"));
        assertEquals((short) 400, thrown.getStatusCode());
    }

    private LevoSatelliteService newService(String organizationId) throws Exception {
        return new LevoSatelliteService(callbacks, "http://localhost:9999", organizationId, "staging");
    }
}

/*
 * OIE OIDC Authentication — engine-side OIDC login plugin.
 *
 * Published under the terms of the Mozilla Public License 2.0.
 */

package org.openintegrationengine.plugins.oidc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Properties;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.mirth.connect.model.User;
import com.mirth.connect.server.controllers.UserController;

class UserProvisionerTest {

    private static final String SUBJECT = "https://idp.example#subject-1";

    private UserController users;
    private User existing;

    @BeforeEach
    void setUp() {
        users = mock(UserController.class);
        existing = new User();
        existing.setId(7);
        existing.setUsername("jdoe");
    }

    private static ClaimsMapper.Identity identity() {
        User profile = new User();
        profile.setUsername("jdoe");
        return new ClaimsMapper.Identity("jdoe", SUBJECT, profile, List.of());
    }

    private static OidcConfig config(boolean jit, String linkedAccounts) {
        Properties p = new Properties();
        p.setProperty("jit.enabled", String.valueOf(jit));
        p.setProperty("linked-accounts", linkedAccounts);
        return OidcConfig.from(p);
    }

    @Test
    void acceptsAnExistingBoundUser() throws Exception {
        when(users.getUser(null, "jdoe")).thenReturn(existing);
        when(users.getUserPreference(7, UserProvisioner.BINDING)).thenReturn(SUBJECT);

        UserProvisioner.Result result = new UserProvisioner(users).provision(identity(), config(true, ""));
        assertEquals(7, result.user().getId());
        assertFalse(result.created());
    }

    @Test
    void rejectsABindingMismatch() throws Exception {
        // The IdP recycled the username for a different person.
        when(users.getUser(null, "jdoe")).thenReturn(existing);
        when(users.getUserPreference(7, UserProvisioner.BINDING)).thenReturn("https://idp.example#someone-else");

        assertThrows(SecurityException.class,
                () -> new UserProvisioner(users).provision(identity(), config(true, "")));
    }

    @Test
    void rejectsAnUnboundExistingAccountUnlessLinked() throws Exception {
        // Local-account takeover guard: an IdP user whose name collides with a
        // pre-existing local account (e.g. admin) must not inherit it.
        when(users.getUser(null, "jdoe")).thenReturn(existing);
        when(users.getUserPreference(7, UserProvisioner.BINDING)).thenReturn(null);

        assertThrows(SecurityException.class,
                () -> new UserProvisioner(users).provision(identity(), config(true, "")));
        verify(users, never()).setUserPreference(any(), any(), any());
    }

    @Test
    void bindsAnExplicitlyLinkedExistingAccount() throws Exception {
        when(users.getUser(null, "jdoe")).thenReturn(existing);
        when(users.getUserPreference(7, UserProvisioner.BINDING)).thenReturn(null);

        UserProvisioner.Result result =
                new UserProvisioner(users).provision(identity(), config(true, "jdoe=" + SUBJECT));
        assertFalse(result.created());
        verify(users).setUserPreference(eq(7), eq(UserProvisioner.BINDING), eq(SUBJECT));
    }

    @Test
    void rejectsAnUnknownUserWhenJitIsOff() throws Exception {
        when(users.getUser(null, "jdoe")).thenReturn(null);

        assertThrows(SecurityException.class,
                () -> new UserProvisioner(users).provision(identity(), config(false, "")));
        verify(users, never()).updateUser(any());
    }

    @Test
    void provisionsAndBindsAnUnknownUserWhenJitIsOn() throws Exception {
        when(users.getUser(null, "jdoe")).thenReturn(null).thenReturn(existing);

        UserProvisioner.Result result = new UserProvisioner(users).provision(identity(), config(true, ""));
        assertTrue(result.created());
        verify(users).updateUser(any(User.class));
        verify(users).setUserPreference(eq(7), eq(UserProvisioner.BINDING), eq(SUBJECT));
    }

    /**
     * An SSO account has no engine password to choose, so no client may run the
     * first-login setup wizard against it — the password that wizard sets is
     * engine-local and SSO never consults it.
     */
    @Test
    void marksFirstLoginSettledSoNoClientAsksAnSsoUserForAPassword() throws Exception {
        when(users.getUser(null, "jdoe")).thenReturn(null).thenReturn(existing);

        new UserProvisioner(users).provision(identity(), config(true, ""));

        verify(users).setUserPreference(eq(7), eq(UserProvisioner.FIRST_LOGIN), eq("false"));
    }

    @Test
    void doesNotRewriteAFirstLoginFlagThatIsAlreadySettled() throws Exception {
        when(users.getUser(null, "jdoe")).thenReturn(existing);
        when(users.getUserPreference(7, UserProvisioner.BINDING)).thenReturn(SUBJECT);
        when(users.getUserPreference(7, UserProvisioner.FIRST_LOGIN)).thenReturn("false");

        new UserProvisioner(users).provision(identity(), config(true, ""));

        verify(users, never()).setUserPreference(any(), eq(UserProvisioner.FIRST_LOGIN), any());
    }

    @Test
    void aFailedFirstLoginWriteNeverFailsTheLogin() throws Exception {
        when(users.getUser(null, "jdoe")).thenReturn(existing);
        when(users.getUserPreference(7, UserProvisioner.BINDING)).thenReturn(SUBJECT);
        org.mockito.Mockito.doThrow(new RuntimeException("preference store down"))
                .when(users).setUserPreference(eq(7), eq(UserProvisioner.FIRST_LOGIN), any());

        assertEquals(7, new UserProvisioner(users).provision(identity(), config(true, "")).user().getId());
    }

    @Test
    void survivesAnInsertRace() throws Exception {
        // Two first logins race the same insert; the loser's updateUser throws
        // but the row is there on re-read.
        when(users.getUser(null, "jdoe")).thenReturn(null).thenReturn(existing);
        org.mockito.Mockito.doThrow(new RuntimeException("duplicate"))
                .when(users).updateUser(any(User.class));
        when(users.getUserPreference(7, UserProvisioner.BINDING)).thenReturn(null);

        UserProvisioner.Result result = new UserProvisioner(users).provision(identity(), config(true, ""));
        assertTrue(result.created());
    }

    @Test
    void failsClosedWhenTheRaceLeavesNoRow() throws Exception {
        when(users.getUser(null, "jdoe")).thenReturn(null).thenReturn(null);

        assertThrows(SecurityException.class,
                () -> new UserProvisioner(users).provision(identity(), config(true, "")));
    }
}

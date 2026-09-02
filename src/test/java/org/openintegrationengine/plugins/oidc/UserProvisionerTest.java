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
import static org.mockito.Mockito.times;

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
        // The IdP-owned profile fields a real token carries; refreshProfile
        // copies these onto a returning user when they differ.
        profile.setEmail("jdoe@example.test");
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
        // Nothing is written on a refused login. The profile refresh once ran
        // BEFORE these checks, so anyone the IdP would issue a token for could
        // claim preferred_username=admin and overwrite the real administrator's
        // name, email and organization — on a login the engine then refused.
        verify(users, never()).updateUser(any(User.class));
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
        verify(users, never()).updateUser(any(User.class));
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
     * The IdP renamed someone. Looking up by username alone misses, and JIT
     * would create a SECOND account bound to the same subject — orphaning the
     * first, which stays bound and becomes loginable again if the old name is
     * ever reissued. The subject binding is authoritative, so the account
     * follows the IdP instead.
     */
    @Test
    void renamesTheBoundAccountWhenTheIdpChangesTheUsername() throws Exception {
        User renamed = new User();
        renamed.setId(7);
        renamed.setUsername("jroe");                       // the old engine name
        // Absent until the rename lands, then found under the new name.
        when(users.getUser(null, "jdoe")).thenReturn(null).thenReturn(existing);
        when(users.getAllUsers()).thenReturn(List.of(renamed));
        when(users.getUserPreference(7, UserProvisioner.BINDING)).thenReturn(SUBJECT);

        UserProvisioner.Result result = new UserProvisioner(users).provision(identity(), config(true, ""));

        assertFalse(result.created(), "an existing account was renamed, not provisioned");
        assertEquals("jdoe", renamed.getUsername());
        verify(users).updateUser(renamed);
    }

    /**
     * Same rename, at IDs above the Integer cache. Every other fixture here uses
     * single-digit ids, which are interned — so an identity comparison written
     * as {@code !=} would pass those and fail only in production, where user ids
     * routinely exceed 127.
     */
    @Test
    void renamesCorrectlyAtIdsAboveTheIntegerCache() throws Exception {
        User renamed = new User();
        renamed.setId(4242);
        renamed.setUsername("jroe");
        User afterRename = new User();
        afterRename.setId(4242);
        afterRename.setUsername("jdoe");
        when(users.getUser(null, "jdoe")).thenReturn(null).thenReturn(afterRename);
        when(users.getAllUsers()).thenReturn(List.of(renamed));
        when(users.getUserPreference(4242, UserProvisioner.BINDING)).thenReturn(SUBJECT);

        UserProvisioner.Result result = new UserProvisioner(users).provision(identity(), config(true, ""));

        assertFalse(result.created());
        assertEquals("jdoe", renamed.getUsername());
    }

    /**
     * Renaming into a name somebody else already holds would merge two
     * identities, which is not a decision to make during a login.
     */
    @Test
    void refusesTheRenameWhenTheNewUsernameIsTaken() throws Exception {
        User boundElsewhere = new User();
        boundElsewhere.setId(9);
        boundElsewhere.setUsername("jroe");
        User occupant = new User();
        occupant.setId(11);
        occupant.setUsername("jdoe");
        // The occupant is what a real getUser returns for this username — every
        // time, not once. The subject search therefore runs from the HIT path,
        // which is the only place this collision is visible.
        when(users.getUser(null, "jdoe")).thenReturn(occupant);
        when(users.getAllUsers()).thenReturn(List.of(boundElsewhere, occupant));
        when(users.getUserPreference(9, UserProvisioner.BINDING)).thenReturn(SUBJECT);
        when(users.getUserPreference(11, UserProvisioner.BINDING)).thenReturn(null);

        assertThrows(SecurityException.class,
                () -> new UserProvisioner(users).provision(identity(), config(true, "")));
        verify(users, never()).updateUser(any(User.class));
    }

    /**
     * A returning user's profile follows the IdP — otherwise an email or name
     * changed there stays stale in the engine forever, and the engine's audit
     * log is where people read it from. Only on an actual difference, so an
     * unchanged login costs no write.
     */
    @Test
    void refreshesProfileFieldsOnReLoginOnlyWhenTheyDiffer() throws Exception {
        existing.setEmail("old@example.test");
        when(users.getUser(null, "jdoe")).thenReturn(existing);
        when(users.getUserPreference(7, UserProvisioner.BINDING)).thenReturn(SUBJECT);

        new UserProvisioner(users).provision(identity(), config(true, ""));
        assertEquals("jdoe@example.test", existing.getEmail());
        verify(users).updateUser(existing);

        // Second login, nothing changed at the IdP: no further write.
        new UserProvisioner(users).provision(identity(), config(true, ""));
        verify(users, times(1)).updateUser(existing);
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

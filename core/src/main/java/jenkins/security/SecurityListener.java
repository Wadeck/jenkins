/*
 * The MIT License
 *
 * Copyright 2013 Jesse Glick.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package jenkins.security;

import hudson.ExtensionList;
import hudson.ExtensionPoint;
import hudson.security.AbstractPasswordBasedSecurityRealm;
import hudson.security.SecurityRealm;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.annotation.Nonnull;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.userdetails.UserDetails;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

/**
 * Listener notified of various significant events related to security.
 *
 * The current implementation is deprecated for external usage and
 * you should use the SecurityListener2 from security-listener-api plugin instead.
 * @since 1.548
 */
@Restricted(NoExternalUse.class)
public abstract class SecurityListener implements ExtensionPoint {
    
    private static final Logger LOGGER = Logger.getLogger(SecurityListener.class.getName());

    public static final String SOURCE_UNKNOWN = "unknown";
    public static final String SOURCE_NEW_PREFIX = "sl2:";

    /**
     * Both methods will be called, so implement only one of the two
     * @see #authenticated(UserDetails, String)
     */
    protected void authenticated(@Nonnull UserDetails details){}

    /**
     * Fired when a user was successfully authenticated by password.
     * This might be via the web UI, or via REST (not with an API token) or CLI (not with an SSH key).
     * Only {@link AbstractPasswordBasedSecurityRealm}s are considered.
     * @param details details of the newly authenticated user, such as name and groups
     * @since TODO
     */
    protected void authenticated(@Nonnull UserDetails details, @Nonnull String source){}

    /**
     * Both methods will be called, so implement only one of the two
     * @see #failedToAuthenticate(String, String)
     */
    protected void failedToAuthenticate(@Nonnull String username){}
    /**
     * Fired when a user tried to authenticate by password but failed.
     * @param username the user
     * @see #authenticated
     * @since TODO
     */
    protected void failedToAuthenticate(@Nonnull String username, @Nonnull String source){}

    /**
     * Both methods will be called, so implement only one of the two
     * @see #loggedIn(String, String)
     */
    protected void loggedIn(@Nonnull String username){}
    /**
     * Fired when a user has logged in via the web UI.
     * Would be called after {@link #authenticated}.
     * @param username the user
     * @since TODO
     */
    protected void loggedIn(@Nonnull String username, @Nonnull String source){}

    /**
     * Both methods will be called, so implement only one of the two
     * @see #failedToLogIn(String, String)
     */
    protected void failedToLogIn(@Nonnull String username){}
    /**
     * Fired when a user has failed to log in via the web UI.
     * Would be called after {@link #failedToAuthenticate}.
     * @param username the user
     * @since TODO
     */
    protected void failedToLogIn(@Nonnull String username, @Nonnull String source){}

    /**
     * Both methods will be called, so implement only one of the two
     * @see #loggedOut(String, String)
     */
    protected void loggedOut(@Nonnull String username){}
    /**
     * Fired when a user logs out.
     * @param username the user
     * @since TODO
     */
    protected void loggedOut(@Nonnull String username, @Nonnull String source){}

    protected @Nonnull String transformSource(@Nonnull String source){
        if(source.startsWith(SOURCE_NEW_PREFIX)){
            // in case we come from the new SecurityListener,
            // we could just remove the prefix to be backward portable
            return source.substring(SOURCE_NEW_PREFIX.length());
        }

        return source;
    }

    /**
     * @see #fireAuthenticated(UserDetails, String)
     * @since 1.569
     */
    public static void fireAuthenticated(@Nonnull UserDetails details) {
        fireAuthenticated(details, SOURCE_UNKNOWN);
    }
    /**
     * Only one of the fireAuthenticated methods should be called, the second one is called implicitly.
     * @since TODO
     */
    public static void fireAuthenticated(@Nonnull UserDetails details, @Nonnull String source) {
        if (LOGGER.isLoggable(Level.FINE)) {
            List<String> groups = new ArrayList<String>();
            for (GrantedAuthority auth : details.getAuthorities()) {
                if (!auth.equals(SecurityRealm.AUTHENTICATED_AUTHORITY)) {
                    groups.add(auth.getAuthority());
                }
            }
            LOGGER.log(Level.FINE, "authenticated: {0} with {1}, from {2}", new Object[] {details.getUsername(), groups, source});
        }
        for (SecurityListener l : all()) {
            l.authenticated(details);
            l.authenticated(details, l.transformSource(source));
        }
    }

    /**
     * @see #fireFailedToAuthenticate(String, String)
     * @since 1.569
     */
    public static void fireFailedToAuthenticate(@Nonnull String username) {
        fireFailedToAuthenticate(username, SOURCE_UNKNOWN);
    }
    /**
     * Only one of the fireFailedToAuthenticate methods should be called, the second one is called implicitly.
     * @since TODO
     */
    public static void fireFailedToAuthenticate(@Nonnull String username, @Nonnull String source) {
        LOGGER.log(Level.FINE, "failed to authenticate: {0}, from {1}", new Object[]{ username, source });
        for (SecurityListener l : all()) {
            l.failedToAuthenticate(username);
            l.failedToAuthenticate(username, l.transformSource(source));
        }
    }

    /**
     * @see #fireLoggedIn(String, String)
     * @since 1.569
     */
    public static void fireLoggedIn(@Nonnull String username) {
        fireLoggedIn(username, SOURCE_UNKNOWN);
    }
    /**
     * Only one of the fireLoggedIn methods should be called, the second one is called implicitly.
     * @since TODO
     */
    public static void fireLoggedIn(@Nonnull String username, @Nonnull String source) {
        LOGGER.log(Level.FINE, "logged in: {0}, from {1}", new Object[]{ username, source });
        for (SecurityListener l : all()) {
            l.loggedIn(username);
            l.loggedIn(username, l.transformSource(source));
        }
    }

    /**
     * @see #fireFailedToLogIn(String, String)
     * @since 1.569
     */
    public static void fireFailedToLogIn(@Nonnull String username) {
        fireFailedToLogIn(username, SOURCE_UNKNOWN);
    }
    /**
     * Only one of the fireFailedToLogIn methods should be called, the second one is called implicitly.
     * @since TODO
     */
    public static void fireFailedToLogIn(@Nonnull String username, @Nonnull String source) {
        LOGGER.log(Level.FINE, "failed to log in: {0}, from {1}", new Object[]{ username, source });
        for (SecurityListener l : all()) {
            l.failedToLogIn(username);
            l.failedToLogIn(username, l.transformSource(source));
        }
    }

    /**
     * @see #fireLoggedOut(String, String)
     * @since 1.569
     */
    public static void fireLoggedOut(@Nonnull String username) {
        fireLoggedOut(username, SOURCE_UNKNOWN);
    }
    /**
     * Only one of the fireLoggedOut methods should be called, the second one is called implicitly.
     * @since TODO
     */
    public static void fireLoggedOut(@Nonnull String username, @Nonnull String source) {
        LOGGER.log(Level.FINE, "logged out: {0}, from {1}", new Object[]{ username, source });
        for (SecurityListener l : all()) {
            l.loggedOut(username);
            l.loggedOut(username, l.transformSource(source));
        }
    }

    private static List<SecurityListener> all() {
        return ExtensionList.lookup(SecurityListener.class);
    }

}

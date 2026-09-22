package org.openintegrationengine.plugins.oidc;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.xml.parsers.DocumentBuilderFactory;

import org.junit.jupiter.api.Test;
import org.w3c.dom.Element;

import com.fasterxml.jackson.databind.ObjectMapper;

/** Exercises the desktop/server classpath boundary declared by the shipped descriptor. */
class ExtensionPackagingTest {
    private static Map<String, String> libraries() throws Exception {
        var factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        var document = factory.newDocumentBuilder().parse(new File("plugin.xml"));
        var nodes = document.getElementsByTagName("library");
        Map<String, String> result = new HashMap<>();
        for (int i = 0; i < nodes.getLength(); i++) {
            var library = (Element) nodes.item(i);
            result.put(library.getAttribute("path"), library.getAttribute("type"));
        }
        return result;
    }

    @Test
    void everyDesktopLibraryIsCoveredByReleaseSigning() throws Exception {
        var signing = new ObjectMapper().readTree(new File(".github/signing/config.json"));
        for (var library : libraries().entrySet()) {
            if (!Set.of("CLIENT", "SHARED").contains(library.getValue())) continue;
            var packagedPath = Path.of("oidcauth", library.getKey());
            boolean covered = false;
            for (var pattern : signing.get("jars")) {
                covered |= FileSystems.getDefault().getPathMatcher("glob:" + pattern.asText())
                        .matches(packagedPath);
            }
            assertTrue(covered, "The desktop launcher requires a signature on " + packagedPath);
        }
    }

    /**
     * Use isolated loaders so Maven's Nimbus dependency cannot hide an incorrect
     * library scope. Engine/provided APIs remain available in both environments.
     */
    private static URLClassLoader loader(Set<String> scopes) throws Exception {
        Map<String, String> declared = libraries();
        Map<String, String> bundledDependencies = new HashMap<>();
        for (var library : declared.entrySet()) {
            if (library.getKey().startsWith("lib/")) {
                bundledDependencies.put(Path.of(library.getKey()).getFileName().toString(), library.getValue());
            }
        }
        assertTrue(scopes.contains(declared.get("oidcauth-shared.jar")),
                "OIDC API classes must remain available on this classpath");
        List<URL> urls = new ArrayList<>();
        Set<String> resolved = new java.util.HashSet<>();
        String classpath = System.getProperty("surefire.test.class.path", System.getProperty("java.class.path"));
        for (String entry : classpath.split(java.util.regex.Pattern.quote(File.pathSeparator))) {
            Path path = Path.of(entry);
            String filename = path.getFileName().toString();
            if (filename.equals("test-classes")) continue;
            String scope = bundledDependencies.get(filename);
            if (scope != null) {
                resolved.add(filename);
                if (!scopes.contains(scope)) continue;
            }
            urls.add(path.toUri().toURL());
        }
        assertTrue(resolved.containsAll(bundledDependencies.keySet()),
                "Every bundled dependency must be represented in the classpath check");
        return new URLClassLoader(urls.toArray(URL[]::new), ClassLoader.getPlatformClassLoader());
    }

    @Test
    void desktopApiLoadsWithoutServerOnlyDependencies() throws Exception {
        try (var desktop = loader(Set.of("CLIENT", "SHARED"))) {
            var api = Class.forName(OidcAdminServletInterface.class.getName(), true, desktop);
            // The desktop registers and reflects servlet interfaces even for web-only plugins.
            assertTrue(api.getMethods().length > 0);
            for (var method : api.getMethods()) {
                method.getAnnotations();
                method.getParameterAnnotations();
            }
            assertThrows(ClassNotFoundException.class,
                    () -> Class.forName("com.nimbusds.jwt.SignedJWT", false, desktop));
            assertThrows(ClassNotFoundException.class,
                    () -> Class.forName("net.jcip.annotations.ThreadSafe", false, desktop));
        }
    }

    @Test
    void serverRetainsTokenValidationDependencies() throws Exception {
        try (var server = loader(Set.of("SERVER", "SHARED"))) {
            assertNotNull(Class.forName("com.nimbusds.jwt.SignedJWT", true, server));
            assertNotNull(Class.forName("net.jcip.annotations.ThreadSafe", true, server));
            var validator = Class.forName(OidcTokenValidator.class.getName(), true, server);
            assertTrue(validator.getDeclaredMethods().length > 0);
            assertTrue(validator.getDeclaredConstructors().length > 0);
        }
    }
}

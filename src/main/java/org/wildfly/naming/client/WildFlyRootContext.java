/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

package org.wildfly.naming.client;

import static java.security.AccessController.doPrivileged;
import static org.jboss.naming.remote.client.InitialContextFactory.CALLBACK_HANDLER_KEY;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.PrivilegedAction;
import java.util.Iterator;
import java.util.Map;
import java.util.ServiceConfigurationError;
import java.util.ServiceLoader;

import javax.naming.Binding;
import javax.naming.CompositeName;
import javax.naming.Context;
import javax.naming.InvalidNameException;
import javax.naming.Name;
import javax.naming.NameClassPair;
import javax.naming.NameParser;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.spi.NamingManager;

import org.wildfly.common.Assert;
import org.wildfly.naming.client._private.Messages;
import org.wildfly.naming.client.util.FastHashtable;
import org.wildfly.naming.client.util.NamingUtils;
import org.xnio.Options;

/**
 * A root context which locates providers based on the {@link Context#PROVIDER_URL} environment property as well as any
 * URL scheme which appears as a part of the JNDI name in the first segment.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:tadamski@redhat.com">Tomasz Adamski</a>
 */
public final class WildFlyRootContext implements Context {
    static {
        Version.getVersion();
    }
    private static final NameParser NAME_PARSER = CompositeName::new;

    private final FastHashtable<String, Object> environment;

    private final Object loaderLock = new Object();
    private final ServiceLoader<NamingProviderFactory> namingProviderServiceLoader;
    private final ServiceLoader<NamingContextFactory> namingContextServiceLoader;

    /**
     * Construct a new instance, searching the thread context class loader for providers.  If no context class loader is
     * set when this constructor is called, the class loader of this class is used.
     *
     * @param environment the environment to use (not copied)
     */
    public WildFlyRootContext(final FastHashtable<String, Object> environment) {
        this(environment, secureGetContextClassLoader());
    }

    /**
     * Construct a new instance, searching the given class loader for providers.
     *
     * @param environment the environment to use (not copied)
     * @param classLoader the class loader to search for providers
     */
    public WildFlyRootContext(final FastHashtable<String, Object> environment, final ClassLoader classLoader) {
        this.environment = EnvironmentUtil.convertEnvironment(environment);
        namingProviderServiceLoader = ServiceLoader.load(NamingProviderFactory.class, classLoader);
        namingContextServiceLoader = ServiceLoader.load(NamingContextFactory.class, classLoader);
    }

    private WildFlyRootContext(final FastHashtable<String, Object> environment, final ServiceLoader<NamingProviderFactory> namingProviderServiceLoader, final ServiceLoader<NamingContextFactory> namingContextServiceLoader) {
        this.environment = EnvironmentUtil.convertEnvironment(environment);
        this.namingProviderServiceLoader = namingProviderServiceLoader;
        this.namingContextServiceLoader = namingContextServiceLoader;
    }

    private static ClassLoader secureGetContextClassLoader() {
        final ClassLoader contextClassLoader;
        final SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            contextClassLoader = doPrivileged((PrivilegedAction<ClassLoader>) WildFlyRootContext::getContextClassLoader);
        } else {
            contextClassLoader = getContextClassLoader();
        }
        return contextClassLoader == null ? WildFlyRootContext.class.getClassLoader() : contextClassLoader;
    }

    private static ClassLoader getContextClassLoader() {
        return Thread.currentThread().getContextClassLoader();
    }

    @Override
    public Object lookup(final String name) throws NamingException {
        Assert.checkNotNullParam("name", name);
        return lookup(getNameParser().parse(name));
    }

    @Override
    public Object lookup(Name name) throws NamingException {
        Assert.checkNotNullParam("name", name);
        final ReparsedName reparsedName = reparse(name);
        if (reparsedName.isEmpty()) {
            return new WildFlyRootContext(environment.clone(), namingProviderServiceLoader, namingContextServiceLoader);
        }
        return getProviderContext(reparsedName.getUrlScheme()).lookup(reparsedName.getName());
    }

    @Override
    public void bind(final String name, final Object obj) throws NamingException {
        Assert.checkNotNullParam("name", name);
        bind(getNameParser().parse(name), obj);
    }

    @Override
    public void bind(final Name name, final Object obj) throws NamingException {
        Assert.checkNotNullParam("name", name);
        final ReparsedName reparsedName = reparse(name);
        getProviderContext(reparsedName.getUrlScheme()).bind(reparsedName.getName(), obj);
    }

    @Override
    public void rebind(final String name, final Object obj) throws NamingException {
        Assert.checkNotNullParam("name", name);
        rebind(getNameParser().parse(name), obj);
    }

    @Override
    public void rebind(final Name name, final Object obj) throws NamingException {
        Assert.checkNotNullParam("name", name);
        final ReparsedName reparsedName = reparse(name);
        getProviderContext(reparsedName.getUrlScheme()).rebind(reparsedName.getName(), obj);
    }

    @Override
    public void unbind(final String name) throws NamingException {
        Assert.checkNotNullParam("name", name);
        unbind(getNameParser().parse(name));
    }

    @Override
    public void unbind(final Name name) throws NamingException {
        Assert.checkNotNullParam("name", name);
        final ReparsedName reparsedName = reparse(name);
        getProviderContext(reparsedName.getUrlScheme()).unbind(reparsedName.getName());
    }

    @Override
    public void rename(final String oldName, final String newName) throws NamingException {
        Assert.checkNotNullParam("oldName", oldName);
        Assert.checkNotNullParam("newName", newName);
        rename(getNameParser().parse(oldName), getNameParser().parse(newName));
    }

    @Override
    public void rename(final Name oldName, final Name newName) throws NamingException {
        Assert.checkNotNullParam("oldName", oldName);
        Assert.checkNotNullParam("newName", newName);
        final ReparsedName oldReparsedName = reparse(oldName);
        final ReparsedName newReparsedName = reparse(newName);
        getProviderContext(oldReparsedName.getUrlScheme()).rename(oldReparsedName.getName(), newReparsedName.getName());
    }

    @Override
    public NamingEnumeration<NameClassPair> list(final String name) throws NamingException {
        Assert.checkNotNullParam("name", name);
        return list(getNameParser().parse(name));
    }

    @Override
    public NamingEnumeration<NameClassPair> list(final Name name) throws NamingException {
        Assert.checkNotNullParam("name", name);
        final ReparsedName reparsedName = reparse(name);
        return CloseableNamingEnumeration.fromEnumeration(getProviderContext(reparsedName.getUrlScheme()).list(
                reparsedName.getName()));
    }

    @Override
    public NamingEnumeration<Binding> listBindings(final String name) throws NamingException {
        Assert.checkNotNullParam("name", name);
        return listBindings(getNameParser().parse(name));
    }

    @Override
    public NamingEnumeration<Binding> listBindings(final Name name) throws NamingException {
        Assert.checkNotNullParam("name", name);
        final ReparsedName reparsedName = reparse(name);
        return CloseableNamingEnumeration.fromEnumeration(getProviderContext(reparsedName.getUrlScheme()).listBindings(
                reparsedName.getName()));
    }

    @Override
    public void destroySubcontext(final String name) throws NamingException {
        Assert.checkNotNullParam("name", name);
        destroySubcontext(getNameParser().parse(name));
    }

    @Override
    public void destroySubcontext(final Name name) throws NamingException {
        Assert.checkNotNullParam("name", name);
        final ReparsedName reparsedName = reparse(name);
        getProviderContext(reparsedName.getUrlScheme()).destroySubcontext(reparsedName.getName());
    }

    @Override
    public Context createSubcontext(final String name) throws NamingException {
        Assert.checkNotNullParam("name", name);
        return createSubcontext(getNameParser().parse(name));
    }

    @Override
    public Context createSubcontext(final Name name) throws NamingException {
        Assert.checkNotNullParam("name", name);
        final ReparsedName reparsedName = reparse(name);
        return getProviderContext(reparsedName.getUrlScheme()).createSubcontext(reparsedName.getName());
    }

    @Override
    public Object lookupLink(final String name) throws NamingException {
        Assert.checkNotNullParam("name", name);
        return lookupLink(getNameParser().parse(name));
    }

    @Override
    public Object lookupLink(final Name name) throws NamingException {
        Assert.checkNotNullParam("name", name);
        final ReparsedName reparsedName = reparse(name);
        if (reparsedName.isEmpty()) {
            return new WildFlyRootContext(environment.clone(), namingProviderServiceLoader, namingContextServiceLoader);
        }
        return getProviderContext(reparsedName.getUrlScheme()).lookupLink(reparsedName.getName());
    }

    @Override
    public NameParser getNameParser(Name name) throws NamingException {
        return getNameParser();
    }

    @Override
    public NameParser getNameParser(String s) throws NamingException {
        return getNameParser();
    }

    private NameParser getNameParser(){
        return NAME_PARSER;
    }

    public String composeName(final String name, final String prefix) throws NamingException {
        Assert.checkNotNullParam("name", name);
        Assert.checkNotNullParam("prefix", prefix);
        return composeName(getNameParser().parse(name), getNameParser().parse(prefix)).toString();
    }

    public Name composeName(final Name name, final Name prefix) throws NamingException {
        return prefix.addAll(name);
    }

    public Object addToEnvironment(final String propName, final Object propVal) {
        return environment.put(propName, propVal);
    }

    public Object removeFromEnvironment(final String propName) {
        return environment.remove(propName);
    }

    @Override
    public FastHashtable<String, Object> getEnvironment() throws NamingException {
        return environment;
    }

    public void close() throws NamingException {
    }

    public String getNameInNamespace() throws NamingException {
        // always root
        return "";
    }

    private Context getProviderContext(final String nameScheme) throws NamingException {
        // get provider scheme
        final Object urlString = getEnvironment().get(PROVIDER_URL);
        URI providerUri;
        try {
            providerUri = urlString == null ? null : new URI(urlString.toString());
        } catch (URISyntaxException e) {
            throw Messages.log.invalidProviderUri(e, urlString);
        }
        final String providerScheme = providerUri == null ? null : providerUri.getScheme();
        // check for empty
        if (providerScheme == null || providerScheme.isEmpty()) {
            // search for context factories which support a null provider
            synchronized (loaderLock) {
                final Iterator<NamingContextFactory> contextIterator = namingContextServiceLoader.iterator();
                for (;;) try {
                    if (! contextIterator.hasNext()) break;
                    final NamingContextFactory contextFactory = contextIterator.next();
                    if (contextFactory.supportsUriScheme(null, nameScheme)) {
                        return contextFactory.createRootContext(null, nameScheme, getEnvironment());
                    }
                } catch (ServiceConfigurationError error) {
                    Messages.log.serviceConfigFailed(error);
                }
            }
            if (nameScheme != null) {
                // there is a name scheme to resolve; try the old-fashioned way
                final Context context = NamingManager.getURLContext(nameScheme, environment);
                if (context != null) {
                    return context;
                }
            }
            // by default, support an empty local root context
            return NamingUtils.emptyContext(getEnvironment());
        }
        // get active naming providers
        final ServiceLoader<NamingProviderFactory> providerLoader = this.namingProviderServiceLoader;
        synchronized (providerLoader) {
            final Iterator<NamingProviderFactory> providerIterator = providerLoader.iterator();
            for (;;) try {
                if (! providerIterator.hasNext()) break;
                final NamingProviderFactory providerFactory = providerIterator.next();
                if (providerFactory.supportsUriScheme(providerScheme, getEnvironment())) {
                    final NamingProvider provider = providerFactory.createProvider(providerUri, getEnvironment());
                    final Iterator<NamingContextFactory> contextIterator = namingContextServiceLoader.iterator();
                    for (;;) try {
                        if (! contextIterator.hasNext()) break;
                        final NamingContextFactory contextFactory = contextIterator.next();
                        if (contextFactory.supportsUriScheme(provider, nameScheme)) {
                            return contextFactory.createRootContext(provider, nameScheme, getEnvironment());
                        }
                    } catch (ServiceConfigurationError error) {
                        Messages.log.serviceConfigFailed(error);
                    }
                }
            } catch (ServiceConfigurationError error) {
                Messages.log.serviceConfigFailed(error);
            }
            if (nameScheme != null) {
                // there is a name scheme to resolve; try the old-fashioned way
                final Context context = NamingManager.getURLContext(nameScheme, environment);
                if (context != null) {
                    return context;
                }
            }
            throw Messages.log.noProviderForUri(nameScheme);
        }
    }

    ReparsedName reparse(final Name origName) throws InvalidNameException {
        final Name name = (Name) origName.clone();
        if (name.isEmpty()) {
            return new ReparsedName(null, name);
        }
        final String first = name.get(0);
        final int idx = first.indexOf(':');
        final String urlScheme;
        if (idx != -1) {
            urlScheme = first.substring(0, idx);
            final String segment = first.substring(idx+1);

            name.remove(0);
            if(segment.length()>0 || (origName.size()>1 && origName.get(1).length()>0)){
                name.add(0, segment);
            }
            return new ReparsedName(urlScheme.isEmpty() ? null : urlScheme, name);
        } else {
            return new ReparsedName(null, name);
        }
    }

    class ReparsedName {
        final String urlScheme;
        final Name name;

        ReparsedName(final String urlScheme, final Name name){
            this.urlScheme = urlScheme;
            this.name = name;
        }

        public String getUrlScheme() {
            return urlScheme;
        }

        public Name getName() {
            return name;
        }

        boolean isEmpty(){
            return urlScheme == null && name.isEmpty();
        }
    }

    private static class EnvironmentUtil {

        private static final String REMOTE_CONNECTIONS = "remote.connections";
        private static final String REMOTE_CONNECTION_PREFIX = "remote.connection.";
        private static final String HOST = "host";
        private static final String PORT = "port";
        private static final String CALLBACK_HANDLER_CLASS = "callback.handler.class";
        private static final String CONNECT_OPTIONS_PREFIX = "connect.options.";
        private static final String USERNAME = "username";
        private static final String PASSWORD = "password";
        private static final String NAMING_CONNECT_OPTIONS_PREFIX = "jboss.naming.client.connect.options.";

        /**
         * Converts legacy EJB connection properties from the environment to naming properties, if possible.
         *
         * @param environment the environment
         * @return the environment after replacing EJB connection properties with naming properties where possible
         */
        private static FastHashtable<String, Object> convertEnvironment(final FastHashtable<String, Object> environment) {
            final String connectionName = (String) environment.getOrDefault(REMOTE_CONNECTIONS, "");
            if (connectionName.isEmpty() || connectionName.contains(",")) {
                // either no EJB connection was specified or multiple EJB connections were specified, can't convert directly to naming properties
                return environment;
            }
            // only one EJB connection was specified, convert its properties to corresponding naming properties
            final FastHashtable<String, Object> convertedEnvironment = new FastHashtable<>(environment.size());
            final String ejbPrefix = REMOTE_CONNECTION_PREFIX + connectionName + ".";
            String host = null;
            String port = null;
            boolean sslEnabled = false;
            for (Map.Entry<String, Object> entry : environment.entrySet()) {
                String property = entry.getKey();
                Object value = entry.getValue();
                if (property.startsWith(ejbPrefix)) {
                    if (property.endsWith(HOST)) {
                        host = (String) value;
                        continue;
                    } else if (property.endsWith(PORT)) {
                        port = (String) value;
                        continue;
                    } else if (property.endsWith(CALLBACK_HANDLER_CLASS)) {
                        property = CALLBACK_HANDLER_KEY;
                    } else if (property.endsWith(USERNAME)) {
                        property = SECURITY_PRINCIPAL;
                    } else if (property.endsWith(PASSWORD)) {
                        property = SECURITY_CREDENTIALS;
                    } else if (property.contains(CONNECT_OPTIONS_PREFIX)) {
                        property = property.replace(ejbPrefix + CONNECT_OPTIONS_PREFIX, NAMING_CONNECT_OPTIONS_PREFIX);
                    } else if (property.endsWith(Options.SSL_ENABLED.getName())) {
                        sslEnabled = value == null ? false : Boolean.parseBoolean((String) value);
                        continue;
                    }
                }
                convertedEnvironment.put(property, value);
            }
            if ((host != null) && (port != null)) {
                final String providerUrl = sslEnabled ? "remote+https://" + host + ":" + port : "remote+http://" + host + ":" + port;
                convertedEnvironment.put(PROVIDER_URL, providerUrl);
            }
            return convertedEnvironment;
        }
    }
}

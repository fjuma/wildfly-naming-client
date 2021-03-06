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

package org.wildfly.naming.client.remote;

import java.io.IOException;
import java.util.Hashtable;

import javax.naming.Binding;
import javax.naming.CommunicationException;
import javax.naming.CompositeName;
import javax.naming.Context;
import javax.naming.Name;
import javax.naming.NameClassPair;
import javax.naming.NamingException;

import org.jboss.remoting3.Connection;
import org.jboss.remoting3.Endpoint;
import org.wildfly.naming.client.AbstractFederatingContext;
import org.wildfly.naming.client.CloseableNamingEnumeration;
import org.wildfly.naming.client._private.Messages;
import org.wildfly.naming.client.store.RelativeFederatingContext;
import org.wildfly.naming.client.util.FastHashtable;
import org.wildfly.naming.client.util.NamingUtils;
import org.xnio.IoFuture;
import org.xnio.OptionMap;

/**
 * The remote-server root context.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
final class RemoteContext extends AbstractFederatingContext {

    private final RemoteNamingProvider provider;
    private final String scheme;

    RemoteContext(final RemoteNamingProvider provider, final String scheme, final Hashtable<String, Object> env) throws CommunicationException {
        super(FastHashtable.of(env));
        this.provider = provider;
        this.scheme = scheme;
    }

    RemoteClientTransport getRemoteTransport() throws NamingException {
        final Endpoint endpoint = Endpoint.getCurrent();
        if (endpoint == null) {
            throw Messages.log.noRemotingEndpoint();
        }
        try {
            final Connection connection = provider.getConnection();
            final IoFuture<RemoteClientTransport> future = RemoteClientTransport.SERVICE_HANDLE.getClientService(connection, OptionMap.EMPTY);
            try {
                return future.getInterruptibly();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                future.cancel();
                throw Messages.log.operationInterrupted();
            }
        } catch (IOException e) {
            if (e.getCause() instanceof NamingException) {
                throw (NamingException) e.getCause();
            }
            throw Messages.log.connectFailed(e);
        }
    }

    protected Object lookupNative(final Name name) throws NamingException {
        if (name.isEmpty()) {
            return new RemoteContext(provider, scheme, getEnvironment());
        }
        return getRemoteTransport().lookup(this, name, false);
    }

    protected Object lookupLinkNative(final Name name) throws NamingException {
        if (name.isEmpty()) {
            return new RemoteContext(provider, scheme, getEnvironment());
        }
        return getRemoteTransport().lookup(this, name, true);
    }

    protected void bindNative(final Name name, final Object obj) throws NamingException {
        getRemoteTransport().bind(name, obj, false);
    }

    protected void rebindNative(final Name name, final Object obj) throws NamingException {
        getRemoteTransport().bind(name, obj, true);
    }

    protected void unbindNative(final Name name) throws NamingException {
        getRemoteTransport().unbind(name);
    }

    protected void renameNative(final Name oldName, final Name newName) throws NamingException {
        getRemoteTransport().rename(oldName, newName);
    }

    protected CloseableNamingEnumeration<NameClassPair> listNative(final Name name) throws NamingException {
        return getRemoteTransport().list(name);
    }

    protected CloseableNamingEnumeration<Binding> listBindingsNative(final Name name) throws NamingException {
        return getRemoteTransport().listBindings(name, this);
    }

    protected void destroySubcontextNative(final Name name) throws NamingException {
        getRemoteTransport().destroySubcontext(name);
    }

    protected Context createSubcontextNative(final Name name) throws NamingException {
        final CompositeName compositeName = NamingUtils.toCompositeName(name);
        getRemoteTransport().createSubcontext(compositeName);
        return new RelativeFederatingContext(getEnvironment(), this, compositeName);
    }

    public void close() {
        // no operation
    }

    public String getNameInNamespace() throws NamingException {
        final String scheme = this.scheme;
        return scheme == null || scheme.isEmpty() ? "" : scheme + ":";
    }
}

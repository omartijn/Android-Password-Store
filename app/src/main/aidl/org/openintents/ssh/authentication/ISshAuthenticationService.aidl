/*
 * Copyright (C) 2017 Christian Hagau.
 * Licensed under the Apache License, Version 2.0.
 * Original: open-keychain/open-keychain/sshauthentication-api
 */
package org.openintents.ssh.authentication;

interface ISshAuthenticationService {
    Intent execute(in Intent intent);
}

-keepattributes SourceFile,LineNumberTable,EnclosingMethod,InnerClasses
-dontobfuscate

-keep class org.eclipse.jgit.internal.JGitText { *; }
-keep class org.bouncycastle.jcajce.provider.** { *; }
-keep class !org.bouncycastle.jce.provider.X509LDAPCertStoreSpi,org.bouncycastle.jce.provider.** { *; }


# OpenKeychain SSH provider AIDL and Parcelable types must keep their Binder wire names.
-keep class org.openintents.ssh.authentication.ISshAuthenticationService { *; }
-keep class org.openintents.ssh.authentication.ISshAuthenticationService$Stub { *; }
-keep class org.openintents.ssh.authentication.ISshAuthenticationService$Stub$Proxy { *; }
-keep class org.openintents.ssh.authentication.SshAuthenticationApiError { *; }

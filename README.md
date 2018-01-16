# JavaDecryptDemo

Apply the JCE Unlimited Strength Jurisdiction Policy Files is *REQUIRED*

To apply the policy files:

Download the Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files from Oracle.

Be sure to download the correct policy file updates for your version of Java:

Java 7 or 8: http://www.oracle.com/technetwork/java/javase/downloads/index.html

Uncompress and extract the downloaded file. The download includes a Readme.txt and two .jar files with the same names as the existing policy files.

Locate the two existing policy files:

local_policy.jar

US_export_policy.jar

On UNIX, look in <java-home>/lib/security/

On Windows, look in C:/Program Files/Java/jre<version>/lib/security/

Replace the existing policy files with the unlimited strength policy files you extracted.

# SecureQueryString
Library to securely encrypt QueryString data

Sometimes we might want to send data from one page to another page using QueryStrings(QS).
But data in the QS is visible to everyone in a plain text format and hence its not a best place to put sensitive data 
as it could be tampered easily.

SecureQueryString.dll is a simple library that help you to encrypt QS data and send it to other page.

Example:

### PageOne.aspx

 SecureQueryString secureQS = new SecureQueryString();
 secureQS.add("Key1","Value1");
 secureQS.add("Key2","Value2");
 
 Response.Redirect("~/PageTwo.aspx?qs="+secureQS);
 
### PageTwo.aspx
 
 SecureQueryString secureQS = new SecureQueryString(Request.QueryString("qs"));
 string val1 = secureQS["Key1"];
 string val2 = secureQS["Key2"];
 
 
 For Hashing default is MD5 but its configurable
 
 For Symmetric Cryptography default is Rijndael but its configurable


# AWS Documentation
I have now spent three months reading and tearing apart the AWS S3 documentation. Writing these tools would have been
easier if their documentation were (1) a bit more consistent (2) a bit more complete. Oh well. That's what trial-and-error
is all about, right?

In the package code, I make a lot of links back to the AWS documentation. On this page, I think I will offer my own
take on the AWS documentation and the work flow. And some of the debugging tricks I had to use. If we improve this tool, we
will break it (see trial-and-error).

# Authentication
AWS is asking two things of your authentication:

1. That YOU are authenticated (with AWS Access key ID and AWS secret key)

2. That your REQUEST is authorized

# Link to AWS Documentation
This link [AWS Documentation](http://docs.aws.amazon.com/AmazonS3/latest/API/Welcome.html) is the best place to start with
information. 

# Request Authorization
Your request is the URL you send to APEX_WEB_SERVICE.MAKE_REST_REQUEST.

AWS will use the request headers you send and your URL to reverse engineer your Canonical Request and your String-To-Sign. 
When you make an error in your request, AWS will (normally) send you back their calculated Canonical Request and their
calculated String-To-Sign. You'll find these in the CLOB that the web service spits back at you. By carefully studing your
canonical request and theirs you will find a different. Fix your end, continue movement. Your error will be that you got the
canonical request wrong or the URL wrong. 

Errors, I have enjoyed thus far:

- AWS escapes parenthesis in object names, the Oracle UTL_URL.ESCAPE function does not
- AWS escapes slashes in the query string but not the prefix

# Host
My favorite confusion throught the process has been the understanding as to what my 'host' is. There are two options. 

1. https://my-bucket.s3.amazonaws.com
2. https://s3.amazonaws.com/my-bucket

Their documentation shows both. The documentation tends to use #1 in early examples. Then uses #2 for examples related to 
specific actions (Operations on Buckets, Operations on Objects). 

You will find some ghost code in the package (left on purpose) that illustrate efforts going back and forth. I have settled 
on #2 as the standard here. #2 is used with the more complicated and advanced procedures. 

## HTTP Request 
![[HTTP-Request.png]]
### Explanation of HTTP Request
#### Request Line
1. **GET / POST**
		The ==GET== *method* indicates that the resource "/" is being requested from the server.
		The ==POST== method indicated that the data is sent to the server.
		    Because there is no name, a symbol like "/" means that the main page of the web server is being requested.
#### Request Header
2. **Host** 
		Nowadays there are web applications that belong to more than one domain found on a single web server, so browsers use the "Host" header to identify which domain the requested resource belongs to.
3. **Cookie** 
		When a web application wants to store information on the client's device, it stores it in a "cookie" header. Cookies are typically used to store session information. This saves you from having to re-enter your username and password when you visit a web application that requires you to log in.
4. **Upgrade-Insecure-Requests** 
		The “Upgrade-Insecure-Requests” header indicates that the client wants to communicate using encryption (SSL).
5. **User-Agent** 
		The “User-Agent” header contains information about the client's browser and operating system. Web servers use this information to send specific HTTP responses to the client. You can find some automated vulnerability scanners by looking under this header.
6. **Accept** 
		The type of data requested is in the “Accept” header.
7. **Accept-Encoding** 
		The type of encoding accepted by the client is found in the “Accept-Encoding” header. You can usually find the names of compression algorithms under this header.
8. **Accept-Language** 
		The “Accept-Language” header contains the client's language information. The web server uses this information to display the prepared content in the client's language.
9. **Connection**
		The “Connection” header shows how the HTTP connection is made. If there is data such as "close", it means that the TCP connection will be closed after receiving the HTTP response. If you see "keep-alive", this means that the connection will be maintained.
10. **Empty line**
		An empty line is inserted between the HTTP request header and the HTTP request message body to create a partition.
#### Request Message Body
11. **Body**
		Any other data to be sent to the web application is in the Request Message Body. If the HTTP POST method is used, then the POST parameters can be found here.

---
## HTTP Response
![[HTTP-Response.png]]
### Explanation of HTTP Response
#### Status Line
1. The **Status Line** contains information about the HTTP version and the HTTP Response Status Code. The HTTP Response Status Code is used to describe the status of the request. There are many HTTP response status codes, but they can be summarized as follows:
	- **100-199**: Informational responses
	- **200-299**: Successful responses
	- **300-399**: Redirection messages
	- **400-499**: Client error responses
	- **500-599**: Server error responses
#### Response Headers
Here are some HTTP Response Headers that you may encounter frequently:
2. **Date**
		The exact time the server sent the HTTP Response to the client.
3. **Connection**
		This indicates how the connection is handled, just like the HTTP Request header.
4. **Server**
		It informs about the operating system of the server and the version of the web server.
5. **Last-Modified**
		It provides information about when the requested resource was modified. This header is used by the caching mechanism.
6. **Content-Type**
		The type of data being sent.
7. **Content-Length**
		The size of the data sent.
8. **Response Body** 
		The HTTP response body contains the resource sent by the server and requested by the client.

---


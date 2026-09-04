# AWS WAF WebSocket

AWS WAF inspects HTTP(S) web requests on associated resources. A WebSocket opening handshake is a regular HTTP upgrade request, so it is in scope wherever WAF sits in front of CloudFront or ALB. After the protocol switches, ALB/CloudFront treat the connection as a persistent WebSocket; AWS WAF does not document frame inspection. API Gateway WebSocket APIs are not a WAF-associable resource. Official docs do not skip WAF because `Upgrade` is present.

## Official: WAF inspects HTTP(S) web requests

“You use AWS WAF to control how your protected resources respond to HTTP(S) web requests.” Associated resources “forward incoming requests to AWS WAF for inspection by the web ACL.”

Owner: [How AWS WAF works](https://docs.aws.amazon.com/waf/latest/developerguide/how-aws-waf-works.html).

Extract: `.sources/how-aws-waf-works.md`

## Official: handshake is a regular HTTP upgrade

CloudFront: “To establish a WebSocket connection, the client sends a regular HTTP request that uses HTTP's upgrade semantics to change the protocol.” Sample client request includes GET, `Upgrade: websocket`, `Connection: Upgrade`, `Sec-WebSocket-Key`, `Sec-WebSocket-Version: 13`. “WebSocket requests must comply with RFC 6455.” After handshake, “either the client or server can send data frames” on the open connection.

Owner: [Use WebSockets with CloudFront distributions](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-working-with.websockets.html).

Extract: `.sources/cloudfront-websockets.md`

ALB: native WebSocket support. “You can upgrade an existing HTTP/1.1 connection into a WebSocket (`ws` or `wss`) connection by using an HTTP connection upgrade. When you upgrade, the TCP connection used for requests (to the load balancer as well as to the target) becomes a persistent WebSocket connection between the client and the target through the load balancer.”

Owner: [Listeners for your Application Load Balancers](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-listeners.html).

Extract: `.sources/alb-listeners-websocket.md`

## Official: after a connection upgrade, ALB WAF integrations no longer apply

“Application Load Balancers also support connection upgrades from HTTP to WebSockets. However, if there is a connection upgrade, Application Load Balancer listener routing rules and AWS WAF integrations no longer apply.” That is post-upgrade, not a skip of the opening HTTP request.

Owner: [How Elastic Load Balancing works](https://docs.aws.amazon.com/elasticloadbalancing/latest/userguide/how-elastic-load-balancing-works.html).

Extract: `.sources/how-elastic-load-balancing-works.md`

## Inference: frames after 101 are not WAF-inspected

AWS WAF’s documented unit of inspection is an HTTP(S) web request. ALB’s documented post-upgrade unit is a persistent WebSocket TCP connection, not further HTTP requests. Official WAF pages do not list WebSocket frames as a request component.

Authority: inference from the official pages above.

## Official: no WAF association for API Gateway WebSocket APIs

Regional WAF resources include “Amazon API Gateway REST API” and Application Load Balancer. WebSocket APIs are not listed.

Owner: [Resources that you can protect with AWS WAF](https://docs.aws.amazon.com/waf/latest/developerguide/how-aws-waf-works-resources.html).

API Gateway’s “Protect your WebSocket APIs” page covers throttling and SSL certificates. It does not mention AWS WAF.

Owner: [Protect your WebSocket APIs in API Gateway](https://docs.aws.amazon.com/apigateway/latest/developerguide/websocket-api-protect.html).

Extracts: `.sources/waf-protectable-resources.md`, `.sources/apigateway-websocket-protect.md`

## Official: Upgrade does not skip WAF

Nothing in the WAF or CloudFront/ALB WebSocket pages says that `Upgrade` / `Connection` skip web-ACL inspection. A GET with those headers is still an HTTP(S) web request.

Owner: [How AWS WAF works](https://docs.aws.amazon.com/waf/latest/developerguide/how-aws-waf-works.html).

## Vendor: managed rules may block the handshake (operators add an allow rule)

AWS Networking & Content Delivery blog: when WAF sits on CloudFront, “the HTTP upgrade request passes through that AWS WAF ACL.” “The WebSocket upgrade is a GET request with no body, and the AWS managed common rule set tends to block it” (403). Their fix is a high-priority rule that allows requests with `Upgrade: websocket` before managed groups. That is an allow-before-managed-rules workaround, not an engine skip.

Owner: [Private AI agent with WebSocket streaming over CloudFront VPC Origins](https://aws.amazon.com/blogs/networking-and-content-delivery/private-ai-agent-with-websocket-streaming-over-cloudfront-vpc-origins-and-the-next-generation-of-opensearch-serverless-for-knowledge-retrieval/).

Extract: `.sources/aws-blog-cloudfront-websocket-waf.md`

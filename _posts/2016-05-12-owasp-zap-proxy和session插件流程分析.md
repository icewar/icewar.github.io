---
layout: post
title:  "ZAP Proxy和Session插件流程分析"
date:   2016-05-11 22:14:54
categories: 源码分析
author: icewar
tags:	扫描器 ZAP分析系列
---

### OWASP ZAP Proxy和Session插件流程分析

* content
{:toc}

OWASP ZAP Proxy是一个HTTP代理服务，采用传统socket方式进行设计，下面介绍zap proxy的实现方式。

![思维导图](/images/201605/20160512-1.png)





 
 ***
  
老规矩找到入口点，入口点在Control类中的init方法

```java
	private boolean init(ControlOverrides overrides) {

		// Load extensions first as message bundles are loaded as a side effect
		loadExtension();

		// ZAP: Start proxy even if no view
	    Proxy proxy = getProxy(overrides);
	    getExtensionLoader().hookProxyListener(proxy);
	    getExtensionLoader().hookPersistentConnectionListener(proxy);
		
		if (view != null) {
		    // ZAP: Add site map listeners
		    getExtensionLoader().hookSiteMapListener(view.getSiteTreePanel());
		}
		
		model.postInit();
		return proxy.startServer();
    }
```  

在上述代码中proxy.startServer();启动了代理服务器代码如下


```java

private ProxyServer proxyServer = null;

//初始化端口、SSL引擎和各种初始化略过

	if (proxyServer.startServer(proxyHost, proxyPort, false) == -1) {
				return false;
		}
```

代码调用了proxyserver类的startserver方法，关键代码如下:

```java
  // ZAP: Set the name of the thread.
        thread = new Thread(this, "ZAP-ProxyServer");
        thread.setDaemon(true);
        // the priority below should be higher than normal to allow fast accept on the server socket
        thread.setPriority(Thread.NORM_PRIORITY + 1);

        proxySocket = null;
        for (int i = 0; i < 20 && proxySocket == null; i++) {
            try {
                proxySocket = createServerSocket(ip, port);
                proxySocket.setSoTimeout(PORT_TIME_OUT);
                isProxyRunning = true;

            } 
            //......此处省略n个字}
            thread.start();
```
创建好proxySocket后开启了线程调用，run方法如下

```java

 @Override
    public void run() {

        Socket clientSocket;
        ProxyThread process;

        while (isProxyRunning) {
            try {
                clientSocket = proxySocket.accept();
                process = createProxyProcess(clientSocket);
                process.start();
                }
```

采用传统阻塞方式等待客户端的链接(想改成AIO，童鞋你怎么看...下面回复吧)，上面方法中关键就是创建了
一个ProxyThread处理类，下面来看看这个类的作用吧，它是一个线程,构造函数不看了，都是赋值，没啥意思
直接看run.下面贴出核心代码

```java

@Override
	public void run() {
        proxyThreadList.add(thread);
		boolean isSecure = this instanceof ProxyThreadSSL;
		HttpRequestHeader firstHeader = null;
		
		try {
			BufferedInputStream bufferedInputStream = new BufferedInputStream(inSocket.getInputStream(), 2048);
			inSocket = new CustomStreamsSocket(inSocket, bufferedInputStream, inSocket.getOutputStream());

			httpIn = new HttpInputStream(inSocket);
			httpOut = new HttpOutputStream(inSocket.getOutputStream());
			
			firstHeader = httpIn.readRequestHeader(isSecure);
            
			if (firstHeader.getMethod().equalsIgnoreCase(HttpRequestHeader.CONNECT)) {
				
				// ZAP: added host name variable
                String hostName = firstHeader.getHostName();
				try {
					httpOut.write(CONNECT_HTTP_200);
					httpOut.flush();
					
					byte[] bytes = new byte[3];
					bufferedInputStream.mark(3);
					bufferedInputStream.read(bytes);
					bufferedInputStream.reset();
					
					if (isSslTlsHandshake(bytes)) {
				        isSecure = true;
						beginSSL(hostName);
					}
			        
			        firstHeader = httpIn.readRequestHeader(isSecure);
			        processHttp(firstHeader, isSecure);
			        }
			        //抓异常、关链接等等，忽略吧

```

上述代码中最关键的就是 processHttp(firstHeader, isSecure)被调用，这个方法里面内容茫茫多...
流程如下:

1、requestHeader封装请求头信息

2、通过HttpSender类处理请求头信息

3、接收到response后回调早已注入进来的插件

先看看回调方法吧  代码如下:

```java
在开头声明了
private static List<HttpSenderListener> listeners = new ArrayList<>();
//只截取了精华部分，核心就是通过Java的多态性调用HttpSenderListener接口的方法，实际调用实在他的实现类里

for (HttpSenderListener listener : listeners) {
				try {
					listener.onHttpRequestSend(msg, initiator, this);
				} catch (Exception e) {
					log.error(e.getMessage(), e);
				}
			}

```

那么问题来了..listeners是在哪里注入进来的呢..

```java

@Override
	public void hook(ExtensionHook extensionHook) {
		super.hook(extensionHook);

		// Register the parameters
		extensionHook.addOptionsParamSet(getParam());

		extensionHook.addSessionListener(this);
		extensionHook.addSiteMapListener(this);
		//重点在这里
		HttpSender.addListener(this);
		//省略省略。。。。。额
```

在插件加载环节中插件的加载流程包括调用hook方法，hook方法执行顺序可参见插件的总接口说明

现在大概懂了是咋回事了吧，其实还有很多插件在这里被回调，默认的有3个，如果你想有自己的扩展只需要参考session插件写就行了。session插件重写了onHttpResponseReceive

这个方法的流程基本就是查看有没有返回Set-Cookie这样的头信息，如果有则对比当前zap是否拥有这个token，token跟域名和端口对应，例如www.baidu.com:80，在后期扫描中如果需要爬虫爬行www.baidu.com，程序则可以直接从session插件中取相应的token即可，如果是主动扫描也是如此。你自己写的插件就不用说了，，任意调用。 

最后附上onHttpRespnseReceive的代码

```java
@Override
	public void onHttpResponseReceive(HttpMessage msg, int initiator, HttpSender sender) {

		//
		if (initiator == HttpSender.ACTIVE_SCANNER_INITIATOR || initiator == HttpSender.SPIDER_INITIATOR
				|| initiator == HttpSender.CHECK_FOR_UPDATES_INITIATOR || initiator == HttpSender.FUZZER_INITIATOR) {
			// Not a session we care about
			return;
		}

		// Check if we know the site and add it otherwise
		String site = msg.getRequestHeader().getHostName() + ":" + msg.getRequestHeader().getHostPort();

		site = ScanPanel.cleanSiteName(site, true);
		if (getView() != null) {
			this.getHttpSessionsPanel().addSiteAsynchronously(site);
		}

		// Check if it's enabled for proxy only
		if (getParam().isEnabledProxyOnly() && initiator != HttpSender.PROXY_INITIATOR) {
			return;
		}

		// Check for default tokens set in response messages
		List<HttpCookie> responseCookies = msg.getResponseHeader().getHttpCookies(msg.getRequestHeader().getHostName());
		for (HttpCookie cookie : responseCookies) {
			// If it's a default session token and it is not already marked as session token and was
			// not previously removed by the user
			if (this.isDefaultSessionToken(cookie.getName()) && !this.isSessionToken(site, cookie.getName())
					&& !this.isRemovedDefaultSessionToken(site, cookie.getName())) {
				this.addHttpSessionToken(site, cookie.getName());
			}
		}

		// Forward the request for proper processing
		HttpSessionsSite sessionsSite = getHttpSessionsSite(site);
		sessionsSite.processHttpResponseMessage(msg);
	}

```




  
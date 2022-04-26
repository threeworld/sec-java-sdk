# 项目介绍

Java 安全 SDK，提供安全的、常见的 Java 安全编码规范和方法，最大限度避免开发中出现常见的漏洞。

# 项目结构

# 常见的漏洞说明

## SQL 注入

### 原理

通过将恶意的 SQL 语句插入到应用的输入参数中，然后在后台 SQL 数据库上解析执行进行的攻击。 其实现的关键条件为：

1. 用户输入可控
2. 后台执行的 SQL 语句拼接了用户构造的数据，进行改变了原有的语义

### 修复方式

1. 采用预编译的方式，是防御 SQL 注入的最佳方式
2. 使用白名单来规范化输入验证方法
3. 黑名单过滤，过滤特殊的 SQL 字符，比如`' "` 等
4. 转义所有的输入，对于用户的输入一律不可信
5. 规范输出，不将报错信息展示在前端，使用统一的错误页面
6. 最小权限原则

### 框架实践

在开发中，一般使用预编译的方式进行防御 SQL 注入。当使用者需要自己编写 SQL 语句时，需要注意使用框架提供的方式或者函数实现预编译。并不是使用 ORM 框架后，就不会用 SQL 注入问题。

#### Mybatis

##### 正确的示例

使用`#{}`语法时，MyBatis 底层会使用`PreparedStatement`方法进行参数变量绑定, 可有效防止 SQL 注入

```xml
<select id="getById" resultType="org.example.User">
	SELECT * FROM user WHERE id = #{id}
</select>
```

##### 错误的示例

使用`${}`语法时，MyBatis 底层会直接注入原始的字符串，即相当于拼接字符串，因此会导致 SQL 注入

```xml
<select id="getByName" resultType="org.example.User">
	SELECT * FROM user WHERE name = ${name} limit 1
</select>
相当于

"select * from user Where name = " + name + "limit 1";
```

##### 特殊情况

1. MyBatis 不支持 else, 需要默认值的情况，可以使用 choose(when, otherwise)

   ```xml
   <select id="getUserListSortBy" resultType="org.example.User">
     SELECT * FROM user
     <if test="sortBy == 'name' or sortBy == 'email'">
   	order by ${sortBy}
     </if>
   </select>
   ```

2. **like 语句:** 使用 bind 标签来构造新参数，然后再使用 #{}。另外需要过滤通配符等特殊字符，避免 DOS。

   ```xml
   <select id="getUserListLike" resultType="org.example.User">
       <bind name="pattern" value="'%' + name + '%'" />
       SELECT * FROM user
       WHERE name LIKE #{pattern}
   </select>
   ```

3. IN 条件，使用`<foreach>` 和 `#{}`

   ```xml
   <select id="selectUserIn" resultType="com.example.User">
     SELECT * FROM user WHERE name in
     <foreach item="name" collection="nameList"
              open="(" separator="," close=")">
           #{name}
     </foreach>
   </select>
   ```

#### Hibernate

Hibernate 支持 HQL (Hibernate Query Language) 和 native SQL 查询，前者存在 HQL 注入，后者和 JDBC 存在相同的注入问题

##### HQL

###### 错误的示例

```java
Query<User> query = session.createQuery("from User where name = '" + name + "'", User.class);
User user = query.getSingleResult();
```

###### 正确的示例 1：位置参数 (Positional parameter)

```java
Query<User> query = session.createQuery("from User where name = ?", User.class);
query.setParameter(0, name);
```

###### 正确的示例 2：命名参数 (named parameter)

```java
Query<User> query = session.createQuery("from User where name = :name", User.class);
query.setParameter("name", name);

//list
Query<User> query = session.createQuery("from User where name in (:nameList)", User.class);
query.setParameterList("nameList", Arrays.asList("lisi", "zhaowu"));

//Javabean
User user = new User();
user.setName("zhaowu");
Query<User> query = session.createQuery("from User where name = :name", User.class);
// User 类需要有 getName() 方法
query.setProperties(user);
```

##### Native SQL

###### 错误的示例

```
String sql = "select * from user where name = '" + name + "'";
Query query = session.createNativeQuery(sql); // Query query = session.createSQLQuery(sql); <deprecated>
```

###### 正确的示例

```
String sql = "select * from user where name = :name";
Query query = session.createNativeQuery(sql); // Query query = session.createSQLQuery(sql); <deprecated>
query.setParameter("name", name);
```

## NoSQL注入

### 原理

和SQL注入原理一样

### 修复方式

1. 【推荐】参数绑定

### 最佳实践

#### mongoDB

##### 错误的示例

拼接用户的查询权限条件

```java
String title = request.getParamenter("name");
MongoCollection<Document> col = mongoClient.getDatabase("MyDB").getCollection("emails");
BasicDBObject query = new BasicDBObject();
query.put("$where", "this.title==\""+ title+"\"");
FindIterable<Document> find = col.find(query);
```

##### 正确的示例

```java
String title = request.getParamenter("name");
MongoCollection<Document> col = mongoClient.getDatabase("MyDB").getCollection("emails");
BasicDBObject query = new BasicDBObject();
query.put("$where", new BasicDBObject("$eq", title));
FindIterable<Document> find = col.find(query);
```

## 文件访问类

### 任意文件上传

#### 原理

因为前端和服务端没有正确的检验上传的文件内容、类型以及路径是否合法导致

#### 修复方式

1. 白名单方式，只允许上传白名单里的后缀文件 **【优先】**
2. 黑名单方式（容易绕过）
3. 上传文件后随机命名（利用时间戳+随机数字组合等）**【优先】**
4. 检测文件内容以及文件Content-Type【Content-Type方式容易绕过】
5. 限定只能上传的文件到指定的目录，不允许目录穿越 **【优先】**

#### 最佳实践

##### 白名单检测文件后缀名

使用File对象的getCanonicalPath方法获取上传文件的实际文件名，若检测到文件名的后缀不是允许的类型（0x00截断，小于JDK1.8），或出现java.io.IOException异常（0x00截断，JDK1.8），或包含冒号（Windows环境中需处理），则说明需要拒绝本次文件上传。

```java
//   base/WhiteAndBlackChecker.java
private List<String> arrayBlackList = new ArrayList<String>();
public List<String> getWhiteList() {
        return arrayWhiteList;
}

//   fileopreate/UploadFileFilter.java
public boolean isValidByWhiteList(File file) throws IOException {

        String fileName = file.getCanonicalFile().getName();
        int index = fileName.lastIndexOf(".");
        String suffix = fileName.substring(index + 1);
        return super.getWhiteList().contains(suffix.toLowerCase());
}
```

##### 限制上传的文件到指定的目录

使用File对象的getCanonicalPath方法获取上传文件的实际路径，和指定目录进行对比，避免使用`../` 实现目录穿越

```java
public boolean isValidByAllowedDirectory(File file, String allowedDirectory) throws IOException {
    String canonicalPath = file.getCanonicalFile().getPath();
    if (System.getProperty("os.name").contains("Window")){
        return canonicalPath.toLowerCase().contains(allowedDirectory.toLowerCase());
    }else{
        return canonicalPath.startsWith(allowedDirectory);
    }
}
```

##### 随机生成文件名

```java
public String generateUniqueFileName(String extName){
    long currentTime = System.currentTimeMillis();
    int num = (int)(new SecureRandom().nextDouble()*10000);
    return currentTime + "" + num + extName;
}
```

### 任意文件下载

#### 原理

服务器没有对下载的文件名和文件路径进行过滤，然而下载的文件名和路径用户是可控的，导致此漏洞存在。

#### 修复方式

1. 在处理下载的代码中对HTTP请求中的待下载文件参数进行过滤，防止出现..等特殊字符，但可能需要处理多种编码方式。
2. 生成File对象后，使用getCanonicalPath获取当前文件的真实路径，判断文件是否在允许下载的目录中，若发现文件不在允许下载的目录中，则拒绝下载。**【推荐】**

#### 最佳实践

##### 限制下载的文件在指定目录

```java
public boolean isValidByAllowedDirectory(File file, String allowedDirectory) throws IOException {
    String canonicalPath = file.getCanonicalFile().getPath();
    if (System.getProperty("os.name").contains("Window")){
        return canonicalPath.toLowerCase().contains(allowedDirectory.toLowerCase());
    }else{
        return canonicalPath.startsWith(allowedDirectory);
    }
}
```

### 任意文件遍历

#### 原理

攻击者可以通过漏洞遍历出服务器操作系统中的任意目录文件名，从而导致服务器敏感信息泄漏，某些场景下(如遍历出网站日志、备份文件、管理后台等)甚至可能会导致服务器被非法入侵。

1. 同级目录遍历 `./`
2. 越级目录遍历`../../../`
3. 绝对路径遍历

#### 修复方式

1. 限制读取的文件和目录

#### 最佳实践

##### 【推荐】限制访问的目录

使用File对象的getCanonicalPath方法获得读取文件的实际路径，和指定目录进行对比，避免使用`../` 实现目录穿越

```java
/**
 * 方式一：检查文件路径是否在允许的目录下
 * @param file  文件的对象
 * @param allowedDirectory 允许的目录
 * @return boolean true为合法，false不合法
 * @throws IOException 异常
 */
public boolean isValidByAllowedDirectory(File file, String allowedDirectory) throws IOException {
    String canonicalPath = file.getCanonicalFile().getPath();
    if (System.getProperty("os.name").contains("Window")){
        return canonicalPath.toLowerCase().contains(allowedDirectory.toLowerCase());
    }else{
        return canonicalPath.startsWith(allowedDirectory);
    }
}
```

##### 低版本JDK（jdk<1.8）禁止空字节访问

示例

```java
/**
 * 检查文件名中是否包含了空字节，禁止出现%00字符截断
 *
 * @param file 访问文件
 * @return 是否包含空字节
 */
private static boolean nullByteValid(File file) {
   return file.getName().indexOf('\u0000') < 1;
}
```

##### 【不推荐】黑名单禁止动态脚本文件后缀

禁止写入如下类型的动态脚本文件：

```
jsp,jspx,jspa,jspf,asp,asa,cer,aspx,php
```

##### 黑名单禁止读取的文件或者路径

```
WEB-INF/web.xml、/etc/passwd、../../../../../../../etc/passwd
```

## 服务端请求伪造

### 原理

攻击者伪造服务器获取资源的请求,通过服务器来攻击内部系统。比如端口扫描,读取默认文件判断服务架构,或者配合SQL注入等其他漏洞攻击内网的主机

### 漏洞触发点

SSRF常出现在URL中,比如分享,翻译,图片加载,文章收藏等功能

### 修复方式

1. 禁用不需要的协议，只允许http和https请求，防止类似于file:///,gopher://,ftp://等引起的问题
2. 将内网IP加入黑名单，请求的地址不能是内网IP
3. 限制请求的端口，比如80，443，8080等，防止端口探测
4. 限制错误信息回显，统一回显错误信息，避免用户根据回显获取信息
5. 视业务而定，采用白名单方式设置允许访问的Host

### 最佳实践

#### 白名单检查主机名是否可信

白名单为域名

```java
/**
 * 通过白名单检查主机名是否可信
 * @param url url
 * @return true/false
 */
public boolean isValidHostByWhiteList(String url){
    URL urlAddress = null;
    try {
        urlAddress = new URL(url);
    } catch (MalformedURLException e) {
        logger.warn("非法的URL" + e);
        return false;
    }
    //获取主域名
    String topDomain = UrlUtils.getTopDomain(url);
    if (topDomain !=null){
        for (String s: super.getWhiteList()){
            if (topDomain.equals(s)){
                return true;
            }
        }
    }
    return false;
}

 public static String getTopDomain(String url){
     try{
         String host = new URL(url).getHost().toLowerCase();
         //查找倒数第二个.的位置
         int index = host.lastIndexOf(".", host.lastIndexOf(".") - 1);
         return host.substring(index + 1);
     }catch(MalformedURLException e){
         logger.warn("非法的URL" + e);
     }
     return null;
 }
```

#### 白名单检测请求的协议是否合法

白名单为允许请求的协议

```java
   /**
     * 白名单检查请求的协议是否合法
     * @param url url
     * @return true/false
     */
    public boolean isValidProtocolByWhiteList(String url){
        try {
            URL urlAddress = new URL(url);
            if (super.getWhiteList().contains(urlAddress.getProtocol())){
                return true;
            }
        } catch (MalformedURLException e) {
            logger.warn("非法的URL" + e);
        }
        return false;
    }
```

#### 黑名单检测请求的协议是否合法

黑名单为禁止使用的协议

```java
/**
     * 黑名单检查请求的协议是否合法
     * @param url url
     * @return true/false
     */
    public boolean isValidProtocolByBlackList(String url){
        try {
            URL urlAddress = new URL(url);
            if (!super.getBlackList().contains(urlAddress.getProtocol())){
                return true;
            }
        } catch (MalformedURLException e) {
            logger.warn("非法的URL" + e);
        }
        return false;
    }
```

#### 【建议】综合以上的防御方式

协议白名单结合黑名单内网IP并判断302跳转

```java
/**
     * 推荐的检测组合，白名单结合内网IP并判断302跳转
     * @param url 需要检测的url
     * @return boolean
     */
    public boolean checkUrl(String url){

        HttpURLConnection httpURLConnection;
        String finalUrl = url;

        try {
            do{
            //判断协议和是否是内网IP
                if (!isValidProtocolByWhiteList(url) && !isInnerIp(url)){
                   return false;
                }
                //处理302跳转
                httpURLConnection = (HttpURLConnection) new URL(finalUrl).openConnection();
                httpURLConnection.setInstanceFollowRedirects(false);//不跟随跳转
                httpURLConnection.setUseCaches(false);//不使用缓存
                httpURLConnection.setConnectTimeout(5*1000);//设置超时时间
                httpURLConnection.connect();//发送dns请求

                int statusCode = httpURLConnection.getResponseCode(); //获取状态码
                if(statusCode>=300 && statusCode<=307 && statusCode!=304 && statusCode!=306){
                    String redirectedURL = httpURLConnection.getHeaderField("Location");
                    if(null==redirectedURL){
                        break;
                    }
                    finalUrl = redirectedURL;//获取跳转之后的url，再次进行判断
                }else{
                    break;
                }
            }while (httpURLConnection.getResponseCode()!=HttpURLConnection.HTTP_OK);//如果没有返回200，则继续对跳转后的链接进行检查
            httpURLConnection.disconnect();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return true;
    }

    /**
     * 判断是否为内网IP
     * @param url 请求的url
     * @return boolean
     */
    private static boolean isInnerIp(String url){

        try {
            URI uri = new URI(url);
            String host = uri.getHost();
            InetAddress inetAddress = InetAddress.getByName(host);
            //获取IP
            String ip = inetAddress.getHostAddress();
            //内网IP段
            String[] blackSubnetList = {"10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","127.0.0.0/8"};
            for (String subnet: blackSubnetList){
                SubnetUtils subnetUtils = new SubnetUtils(subnet);
                if (subnetUtils.getInfo().isInRange(ip)){
                    return true; //如果IP段在内网中，返回
                }
            }
        } catch (URISyntaxException | UnknownHostException e) {
            logger.warn("解析错误uri " + e);
        }
        return false;
    }
```

## URL重定向漏洞

### 原理

后台服务器在告知浏览器跳转时，未对客户端传入的重定向地址进行合法性校验，导致用户浏览器跳转到钓鱼页面的一种漏洞。

### 修复方式

1. 如果只希望在当前的域跳转，可做白名单限制，非白名单内的URL禁止跳转；
2. 如果业务需要，可对于白名单内的地址，用户可无感知跳转，不在白名单内的地址**给用户风险提示**，用户选择是否跳转

### 最佳实践

#### 检测跳转的URL是否在白名单上

```java
/**
     * 检查跳转的URL是否在白名单上
     * @param url 检测的URL
     * @return boolean
     */
    public boolean isWhiteList(String url){

        //只允许http, https
        String u = url.toLowerCase().trim();
        if (!Pattern.matches("^https?.*$", u)){
            return false;
        }
        URI uri = null;
        try {
            uri = new URI(u);
            String host = uri.getHost();
            //获取主域名
            String topDomain = UrlUtils.getTopDomain(u);
            List<String> whiteList = super.getWhiteList();
            //如果域名在白名单或者主域名在白名单
            if (whiteList.contains(host) || whiteList.contains(topDomain)){
                return true;
            }
        } catch (URISyntaxException e) {
            logger.warn("解析url错误：" + e );
        }
        return false;
    }
```

#### 不在白名单内的地址给用户风险提示

通过统一的跳转风险提示页面，让用户选择是否跳转。

## 其他问题

### 统一错误页

在web.xml中定义error-page，防止当出现错误时暴露服务器信息。

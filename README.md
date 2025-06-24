# 项目介绍

Java 安全 SDK，提供安全的、常见的 Java 安全编码规范和方法，最大限度避免开发中出现常见的漏洞。

# 项目结构

源码完善后上传

# 常见的漏洞和对应的安全编码方法

[SQL注入](#sqlInjection)

[NoSQL注入](#NosqlInjection)

[文件访问类](#fileoperate)

[服务端请求伪造](#ssrf)

[URL重定向漏洞](#urlredirect)

[命令注入](#cmdinjection)

[XSS](#xss)

[其他问题](#other)

## <span id="sqlInjection">SQL注入</span>

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

   <!-- 安全的写法 - 使用参数化查询 -->
   <select id="getUsers" resultType="User">
    SELECT * FROM users 
    ORDER BY 
    <choose>
        <when test="orderBy == 'name'">name</when>
        <when test="orderBy == 'age'">age</when>
        <when test="orderBy == 'email'">email</when>
        <otherwise>id</otherwise>
    </choose>
    <choose>
        <when test="direction == 'desc'">DESC</when>
        <otherwise>ASC</otherwise>
    </choose>
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

​		参数有多个时，一种可以使用`@Param("xxx")`进行参数绑定，另一种可以通过`Map`来传参数。

@Param("xxx")方式	

```java
List<User> selectByIdSet(@Param("name")String name, @Param("ids")String[] idList);
 
<select id="selectByIdSet" resultMap="BaseResultMap">
	SELECT
	<include refid="Base_Column_List" />
	from t_user
	WHERE  name=#{name,jdbcType=VARCHAR} and id IN
	<foreach collection="ids" item="id" index="index"
			 open="(" close=")" separator=",">
	  #{id}
	</foreach>
</select>
```

Map方式

```java
Map<String, Object> params = new HashMap<String, Object>(2);
params.put("name", name);
params.put("idList", ids);
mapper.selectByIdSet(params);
 
<select id="selectByIdSet" resultMap="BaseResultMap">  
     select  
     <include refid="Base_Column_List" />  
     from t_user where 
     name = #{name}
     and ID in  
     <foreach item="item" index="index" collection="idList" open="(" separator="," close=")">  
      #{item}  
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

## <span id="NosqlInjection">NoSQL注入</span>

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

## <span id="fileoperate">文件访问类 </span>

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

##### 随机生成文件名并限定后缀

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

## <span id="ssrf">服务端请求伪造 </span>

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

## <span id="urlredirect">URL重定向漏洞</span>

### 原理

后台服务器在告知浏览器跳转时，未对客户端传入的重定向地址进行合法性校验，导致用户浏览器跳转到钓鱼页面的一种漏洞。

### 修复方式

1. 如果只希望在当前的域跳转，可做白名单限制，非白名单内的URL禁止跳转；
2. 如果业务需要，可对于白名单内的地址，用户可无感知跳转，不在白名单内的地址**给用户风险提示**，用户选择是否跳转
3. 如果某个业务已经确定将要跳转的网站，最稳妥的方式是将其编码在源代码中，通过URL中传入的参数来映射跳转网址。

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

## <span id="cmdinjection"> 命令注入 </span>

### 原理

命令执行漏洞是指应用有时需要调用一些执行系统命令的函数，如果系统命令代码未对用户可控参数进行过滤，则当用户能控制这些函数的参数时，就可以将恶意系统命令拼接到正常命令中，从而造成命令执行工具。

危害：

1. 集成web服务程序的权限去执行系统命令或读/写文件
2. 反弹shell
3. 控制整个网站甚至服务器进行进一步的内网渗透

### 修复方式

1. 非必要不要拼接用户的输入作为命令进行执行
2. 如果业务需要，使用白名单
3. 精确匹配和限制用户提交的数据（前端后端都增加限制）

### 最佳实践

#### 错误的示例

```java
 public void test(HttpServletRequest request){
     String ip = request.getParameter("ip");
     //不加过滤直接拼接到执行的命令中
     String exec = "ping "+ip;
     ProcessBuilder p = null;
     BufferedReader reader = null;
     try {
         //调用shell进行执行
         p = new ProcessBuilder("bash","-c",exec);
         p.start();
         String line;
         reader = new BufferedReader(new InputStreamReader(p.start().getInputStream(),"GBK"));
         while((line=reader.readLine())!=null){
             //System.out.println(line);
         }
     } catch (IOException e) {
         e.printStackTrace();
     }finally {
         try {
             reader.close();
         } catch (IOException e) {
             e.printStackTrace();
         }
     }
 }
```

#### 正确的示例

通过精确匹配用户输入的数据，不符合一律不执行，其次可以通过白名单方式匹配允许执行的命令。具体实现见源码`exec/ExecCmdFilter.java`

```java
 public void setRegex(String regex) {
        this.regex = regex;
    }

    public String getRegx() {
        return regex;
    }

    /**
     * 判断用户提供的命令是否合法
     * @param cmd 需要检测的命令
     * @return boolean 是否合法
     */
    private String regex;

    public boolean isValidCMD(String cmd){
        String processedCmd = cmd.trim();
        //精确匹配拼接用户输入的数据
        //正则表达式为自定义
        Boolean isMatch = Pattern.matches(regex, processedCmd);
        Boolean isWhite = super.getWhiteList().contains(processedCmd);

        return isMatch || isWhite;
    }

//测试代码
public class ExecCmdFilterTest {

    @Test
    public void testIsValidCMD(){


        ExecCmdFilter cmdFilter = ExecCmdFilter.getInstance();
        //匹配IP的正则表达式
        String regex = "((?:(?:25[0-5]|2[0-4]\\d|[01]?\\d?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|[01]?\\d?\\d))";
        cmdFilter.setRegex(regex);
        String cmd = "127.0.0.1;ls";
        if (cmdFilter.isValidCMD(cmd)){
            System.out.println("执行的命令合法");
        }else{
            System.out.println("执行的命令不合法");
        }
    }
}
```

## <span id="xss"> XSS </span>

### 原理

Cross-Site Scripting（跨站脚本攻击）简称 XSS，是一种代码注入攻击。攻击者通过在目标网站上注入恶意脚本，使之在用户的浏览器上运行。利用这些恶意脚本，攻击者可获取用户的敏感信息如 Cookie、SessionID 等，进而危害数据安全。

注入的方法

- 在 HTML 中内嵌的文本中，恶意内容以 script 标签形成注入。
- 在内联的 JavaScript 中，拼接的数据突破了原本的限制（字符串，变量，方法名等）。
- 在标签属性中，恶意内容包含引号，从而突破属性值的限制，注入其他属性或者标签。
- 在标签的 href、src 等属性中，包含 `javascript:` 等可执行代码。
- 在 onload、onerror、onclick 等事件中，注入不受控制代码。
- 在 style 属性和标签中，包含类似 `background-image:url("javascript:...");` 的代码（新版本浏览器已经可以防范）。
- 在 style 属性和标签中，包含类似 `expression(...)` 的 CSS 表达式代码（新版本浏览器已经可以防范）。

### 修复方式

目前主流最新版浏览器对内置了预防XSS的措施。**防御XSS的核心就是对不可信数据进行正确的编码。所以只有在正确的地方使用正确的编码才能消除XSS漏洞。**

1. 预防存储型和反射型 XSS通常有两种做法
   1. 改成纯前端渲染，把代码和数据分隔开。要避免DOM型XSS
   2. 对 HTML 做充分转义
2. 使用HttpOnly，禁止页面通过JavaScript访问cookie
3. 输入检查
   1. 输入检查基本先在用户浏览器中进行。例如， 用户注册时的用户名，当要求只能为字母、数字的组合时，就需要进行严格的过滤。其他的，比如电话、邮件、生日等等，都要有一定 的格式规范。对特殊字符进行编码或者过滤。在服务端代码也需要进行输入规范的逻辑检查。
   2. 客户端使用JavaScript检查可以阻挡大部分正常用户的误操作，减小服务端再次验证的资源浪费。
4. 输出检查
5. 预防DOM 型 XSS 攻击，在使用 `.innerHTML`、`.outerHTML`、`document.write()` 时要特别小心，不要把不可信的数据作为 HTML 插到页面上，而应尽量使用 `.textContent`、`.setAttribute()` 等。
6. Content Security Policy

### 最佳实践

java工程中，常用的转义库为 `org.owasp.encoder`

```java
//插入不可信数据到HTML标签之间时，进行HTML Entity编码
String encodedContent = ESAPI.encoder().encodeForHTML(request.getParameter(“input”));

//插入不可信数据到HTML属性里时，进行HTML属性编码
String encodedContent = ESAPI.encoder().encodeForHTMLAttribute(request.getParameter(“input”));

//插入不可信数据到SCRIPT里时，进行JavaScript编码
String encodedContent = ESAPI.encoder().encodeForJavaScript(request.getParameter(“input”));

//插入不可信数据到Style属性里时，进行CSS编码
String encodedContent = ESAPI.encoder().encodeForCSS(request.getParameter(“input”));

//插入不可信数据到HTML URL里时，进行URL编码
//当需要往HTML页面中的URL里插入不可信数据的时候，需要对其进行URL编码，如下：
//<a href=”http://www.abcd.com?param=…插入不可信数据前，进行URL编码…”> Link Content </a>
String encodedContent = ESAPI.encoder().encodeForURL(request.getParameter(“input”));
```

## <span id="spel"> SPEL表达式注入</span>

### 原理

产生SpEL表达式注入漏洞的大前提是存在SpEL的相关库。产生SpEL表达式注入漏洞主要原因是，很大一部分开发人员未对用户输入进行处理就直接通过解析引擎对SpEL继续解析。一旦用户能够控制解析的SpEL语句，便可以通过反射的方式构造执行的命令，从而达到RCE的目的。

### 修复方式

1. 使用 `SimpleEvaluationContext` 替换 `StandardEvaluationContext`，该类抛弃了Java类型引用、构造函数及bean引用

### 最佳实践

示例：

```java
String spel = "T(java.lang.Runtime).getRuntime().exec(\"calc\")";
ExpressionParser parser = new SpelExpressionParser();
Student student = new Student();
EvaluationContext context =SimpleEvaluationContext.forReadOnlyDataBinding().withRootObject(student).build();
Expression expression = parser.parseExpression(spel);
System.out.println(expression.getValue(context));
```

## <span id="other">其他问题</span>

### 统一错误页

在web.xml中定义error-page，防止当出现错误时暴露服务器信息。

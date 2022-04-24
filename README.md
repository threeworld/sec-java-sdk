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

## 文件操作

### 文件上传

#### 1.1 原理

#### 1.2 修复方式

#### 1.3 最佳实践

### 文件下载

#### 1.1 原理

#### 1.2 修复方式

#### 1.3 最佳实践

### 文件遍历

#### 1.1 原理

#### 1.2 修复方式

#### 1.3 最佳实践

## 服务端请求伪造

### 原理

### 修复方式

#### 最佳实践

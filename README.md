# jax-rs-jwt-feature 
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/korbei/jax-rs-jwt-feature/blob/master/LICENSE)

# Usage

Clone this repository and build the project
```
git clone https://github.com/korbei/jax-rs-jwt-feature.git
cd jax-rs-jwt-feature
mvn clean install
```
Add the following maven dependency to your project
```xml
<dependency>
  <groupId>com.korbei.rs</groupId>
  <artifactId>jax-rs-jwt-feature</artifactId>
  <version>1.0-SNAPSHOT</version>
</dependency>
```
Register the feature
```java
@ApplicationPath("/api")
public class App extends Application {

    @Override
    public Set<Class<?>> getClasses() {
        final Set<Class<?>> classes = new HashSet<>();
        ...
        classes.add(JwtDynamicFeature.class);
        return classes;
    }
}
```
Securing your REST endpoints with JSR-250 annotations such as 
- [`@RolesAllowed`](https://docs.oracle.com/javaee/7/api/javax/annotation/security/RolesAllowed.html)
- [`@PermitAll`](https://docs.oracle.com/javaee/7/api/javax/annotation/security/PermitAll.html)
- [`@DenyAll`](https://docs.oracle.com/javaee/7/api/javax/annotation/security/DenyAll.html)
> Resource methods (or classes) without security annotation are exposed as public endpoints

Overwrite the DefaultJwtConfigurationProvider

Generating token

TODO

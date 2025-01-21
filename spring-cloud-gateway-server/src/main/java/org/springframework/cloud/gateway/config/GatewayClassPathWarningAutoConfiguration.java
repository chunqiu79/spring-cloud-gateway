/*
 * Copyright 2013-2020 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.cloud.gateway.config;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.cloud.gateway.support.MvcFoundOnClasspathException;
import org.springframework.context.annotation.Configuration;

/**
 * 装配的条件：
 * 1. 在GatewayAutoConfiguration之前装配
 * 2. spring.cloud.gateway.enabled=true（当然，如果没有配置，也是生效的）
 *
 */
@Configuration(proxyBeanMethods = false)
@AutoConfigureBefore(GatewayAutoConfiguration.class)
@ConditionalOnProperty(name = "spring.cloud.gateway.enabled", matchIfMissing = true)
public class GatewayClassPathWarningAutoConfiguration {

	private static final Log log = LogFactory.getLog(GatewayClassPathWarningAutoConfiguration.class);

	private static final String BORDER = "\n\n**********************************************************\n\n";

	/**
	 * @Configuration(proxyBeanMethods = false)
	 * proxyBeanMethods默认是true
	 * 如果配置成false，那么就说明不需要走cglib动态代理，不是单例的，每次获取的bean都是不同的bean
	 *
	 * @ConditionalOnClass(name = "org.springframework.web.servlet.DispatcherServlet")
	 * 表明只有当类路径中存在 org.springframework.web.servlet.DispatcherServlet 类时，Spring 才会加载这个配置类
	 *
	 * @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
	 * 表示只有在当前应用是一个 Servlet 类型的 Web 应用时，Spring 才会加载这个配置类
	 * // TODO: 2024/6/5 这个有空再看，底层是继承了FilteringSpringBootCondition
	 *
	 * protected static
	 * 表示是一个内部静态类，被标记为 protected，通常表示它是仅供内部使用的配置类
	 *
	 * 所以：类路径中有 DispatcherServlet 类且是 Servlet 类型的 Web 应用时，抛出一个MvcFoundOnClasspathException异常
	 * 检查项目是否错误导入 spring-boot-starter-web 依赖
	 */
	@Configuration(proxyBeanMethods = false)
	@ConditionalOnClass(name = "org.springframework.web.servlet.DispatcherServlet")
	@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
	protected static class SpringMvcFoundOnClasspathConfiguration {

		public SpringMvcFoundOnClasspathConfiguration() {
			throw new MvcFoundOnClasspathException();
		}

	}

	/**
	 * 检查项目是否正确导入 spring-boot-starter-webflux 依赖
	 */
	@Configuration(proxyBeanMethods = false)
	@ConditionalOnMissingClass("org.springframework.web.reactive.DispatcherHandler")
	protected static class WebfluxMissingFromClasspathConfiguration {

		public WebfluxMissingFromClasspathConfiguration() {
			log.warn(BORDER + "Spring Webflux is missing from the classpath, "
					+ "which is required for Spring Cloud Gateway at this time. "
					+ "Please add spring-boot-starter-webflux dependency." + BORDER);
		}

	}

}

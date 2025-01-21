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

import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.client.loadbalancer.reactive.ReactiveLoadBalancer;
import org.springframework.cloud.gateway.config.conditional.ConditionalOnEnabledGlobalFilter;
import org.springframework.cloud.gateway.filter.LoadBalancerServiceInstanceCookieFilter;
import org.springframework.cloud.gateway.filter.ReactiveLoadBalancerClientFilter;
import org.springframework.cloud.loadbalancer.config.LoadBalancerAutoConfiguration;
import org.springframework.cloud.loadbalancer.support.LoadBalancerClientFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.DispatcherHandler;

/**
 * 负载均衡自动配置类
 * 如：当前请求路由到order服务，但是order服务后端有3台机器，当前请求具体发送到那台机器呢？由负载均衡算法决定
 *
 * 装配条件：
 * 1.@ConditionalOnClass({ ReactiveLoadBalancer.class, LoadBalancerAutoConfiguration.class, DispatcherHandler.class })
 * 表明ReactiveLoadBalancer、LoadBalancerAutoConfiguration、DispatcherHandler 3个类需要在类路径下才会生效
 *
 * 2.@AutoConfigureAfter(LoadBalancerAutoConfiguration.class)
 * 表明需要在LoadBalancerAutoConfiguration之后装配
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnClass({ ReactiveLoadBalancer.class, LoadBalancerAutoConfiguration.class, DispatcherHandler.class })
@AutoConfigureAfter(LoadBalancerAutoConfiguration.class)
@EnableConfigurationProperties(GatewayLoadBalancerProperties.class)
public class GatewayReactiveLoadBalancerClientAutoConfiguration {

	/**
	 * 装配条件：
	 * 1.@ConditionalOnBean(LoadBalancerClientFactory.class)
	 * 存在LoadBalancerClientFactory的bean
	 *
	 * 2.@ConditionalOnMissingBean(ReactiveLoadBalancerClientFilter.class)
	 * 没有ReactiveLoadBalancerClientFilter的bean（避免重复创建）
	 *
	 * 3.@ConditionalOnEnabledGlobalFilter
	 * // TODO: 2024/6/5 等有空再研究下
	 */

	@Bean
	@ConditionalOnBean(LoadBalancerClientFactory.class)
	@ConditionalOnMissingBean(ReactiveLoadBalancerClientFilter.class)
	@ConditionalOnEnabledGlobalFilter
	public ReactiveLoadBalancerClientFilter gatewayLoadBalancerClientFilter(LoadBalancerClientFactory clientFactory,
			GatewayLoadBalancerProperties properties) {
		return new ReactiveLoadBalancerClientFilter(clientFactory, properties);
	}

	@Bean
	@ConditionalOnBean({ ReactiveLoadBalancerClientFilter.class, LoadBalancerClientFactory.class })
	@ConditionalOnMissingBean
	@ConditionalOnEnabledGlobalFilter
	public LoadBalancerServiceInstanceCookieFilter loadBalancerServiceInstanceCookieFilter(
			LoadBalancerClientFactory loadBalancerClientFactory) {
		return new LoadBalancerServiceInstanceCookieFilter(loadBalancerClientFactory);
	}

}

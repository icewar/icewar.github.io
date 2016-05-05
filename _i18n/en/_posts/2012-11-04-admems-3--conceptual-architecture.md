---
layout: post
title: "ADMEMS架构方法 (3) – Conceptual Architecture"
subtitle: 
cover_image: 
excerpt: 
category: 
tags: [architecture, software]
---

### 序幕

架构新手通常认为“架构=模块+接口”，有经验的架构师不会一上来就定义接口，面对大项目，他们会在架构早期注重识别重大需求、特色需求、高风险需求。

概念架构时，一定要把产品的价值搞透彻，明确客户需求。

> 顶级设计者在设计中并不是按部就班地采用自顶向下或是自底向上的方法，而是着眼于权重更大的目标。这些目标通常是难点问题，设计者不能轻易地看出这些问题的解决方案。为了得到整个问题的设计方案，设计者必须先治理与难点的设计并消除其中的疑惑。

> —Robert Glass, 《软件工程的事实与谬误》

### 什么是概念架构

Dana Bredemeyer：

> 概念性架构界定了系统的高层组件，以及他们之间的关系，对系统进行了适当的分解，而不陷入细节。

> The Conceptual Architecture identifies the high-level components of the system, and the relationships among them. Its purpose is to direct attention at an appropriate decomposition of the system without delving into details.

### 业界现状

__错误1__：认为架构是功能需求驱动的。而架构应该是功能、质量和约束一同驱动的

__错误2__：认为架构是用例驱动的。这个说法有待商榷。业内有不少人认同这个说法。不过大多数时候，架构只被20%左右的用例驱动，根据这些用例来设计、实现、测试。还有不少时候，并不是用例在驱动架构设计。

__错误3__：“阶段”和“视图”分不清。阶段是先后关系，视图是并列关系。

记住：重大需求塑造概念架构

### 概念架构流程

#### 第一步：初步架构

用Robustness Diagram画出每个用例需要哪些对象参与。例如：

![]({{ site.url }}/images/blog/20121101.png)

##### 初步设计的经验

* 实体对象≠持久化对象
* Controller不要太多
* 不要过于关注细节和UI

#### 第二步：高层分割

“架构=模块+接口”的不足可以概括为两点：

1. 忽视了多视图。软件系统中会涉及到开发视图、运行视图、物理视图、数据视图等。
2. 忽略了概念架构设计

高层分割一般有两种思路

* 切系统为系统：大的系统可以进行两级高层切分
* 切系统为子系统：非常经典的做法，最常见的方式就是分层。

![]({{ site.url }}/images/blog/20121102.png)

切系统为系统的例子：

![]({{ site.url }}/images/blog/20121103.png)

切系统为子系统的例子：

![]({{ site.url }}/images/blog/20121104.png)

### 分层式架构实践

常见的分层方式

* Layer：逻辑分层
* Tier：物理分层，按分布在不同的物理机器上分层。
* 通用性分层
* 技术堆叠

关于Tier分层，架构是要看“能分布”的能力，不是看实际部署情况。

> 我们通常说的Java EE应该是N-layer的，因为 从逻辑上看，Java EE里面有表现层、业务逻辑层和数据层。从物理上而言，这3层可以在不同的tier，也可以在同一个tier。比如，如果服务器、数据库都在一台笔记本上，就是1 tier。

关于通用性，一般来说，通用性越大，层次越靠下。比如，Google有一个基础设施部门，专门负责做最底层的API。这些API的通用性就非常大。

技术堆叠不是独立的架构模式，而是基于分层架构提供的进一步说明。是根据不同的技术实现的分层。比如MVC，按照Controller, Model, View这些不同技术来分层的

注意考虑非功能需求

使用“目标-场景-决策”表是一个不错的技巧。

例如：

![]({{ site.url }}/images/blog/20121105.png)

# VISION DOCUMENT
## [Product Name] — Where We Are Going

**Document Version:** 1.0
**Status:** Draft for review
**Authors:** Founding Team
**Date:** [Current]
**Classification:** Confidential

---

## DOCUMENT PURPOSE

The PRD says what we are building. This document says why and where it leads. The PRD is committed scope. This document is aspirational direction. Both are needed: the PRD aligns engineering on near-term execution; the Vision aligns recruiting, fundraising, partnerships, and long-term decisions on the destination.

This is a document for:
- Investors deciding whether to fund the journey
- Candidates deciding whether to join the journey
- Customers deciding whether to bet on us as long-term partners
- Partners deciding whether to integrate
- The team deciding what to do when faced with hard tradeoffs

When in doubt, the Vision should answer: "Does this decision move us toward our destination?"

---

## 1. THE WORLD WE WANT TO LIVE IN

In ten years, the work of cybersecurity defense looks fundamentally different than today.

Security teams do not spend their days triaging alert queues. They do not fight to keep up with cloud configuration drift across thousands of resources. They do not manually map findings to compliance frameworks before audits. They do not investigate routine incidents from raw logs. They do not spend nights and weekends executing remediations that should have been automatic.

Instead, security teams architect controls, design defensive strategy, develop talent, build relationships with the business, and apply human judgment to the genuinely hard problems — the novel attacks, the strategic decisions, the ethical questions.

The operational work — the detection, the prioritization, the routine remediation, the compliance evidence collection, the incident triage, the threat intelligence correlation — happens autonomously. Continuously. Across every environment the organization operates in. Cloud, on-premises, factory floor, hospital, branch office, classified enclave.

Defenders gain force multiplication of 10x or more from their current baseline. Each security analyst becomes effective across orders of magnitude more workloads. Each CISO can defend organizations of vastly larger scope than today.

The economic asymmetry between attackers and defenders shifts toward defenders for the first time since the cloud era began.

This is the world we want to live in. This is the world we are building toward.

---

## 2. WHY THIS IS POSSIBLE NOW

Every founder claims their moment is uniquely now. We try to be honest about why this is actually true.

### 2.1 The detection layer has commoditized

Five years ago, detecting cloud misconfigurations at scale required proprietary technology. Wiz built the Security Graph. CrowdStrike built Falcon. Palo Alto built Prisma. Each represented hundreds of engineering-years.

Today, open-source equivalents exist for most of this work. Prowler. Trivy. Falco. Checkov. Cartography. Kubescape. Trufflehog. PMapper. Together they provide 75-85% of CNAPP detection capability under permissive licenses.

This is not because the open-source community decided to give away security technology. It is because the underlying problems — pattern matching against known signatures, scanning for known CVEs, correlating known indicators — are fundamentally well-understood. Once a detection technique is published in research papers and conference talks, replicating it is engineering, not science.

The detection layer commoditizing means new entrants do not need hundreds of millions of dollars and years of R&D to compete on detection capability. They can build from open foundations and focus innovation higher in the stack.

### 2.2 Foundation models reached operational quality

Eighteen months ago, large language models were impressive demos for narrow tasks. They hallucinated regularly. They could not reliably reason across long contexts. They could not reliably use tools.

The current generation — Claude Sonnet, Claude Opus, GPT-4 class — has crossed a threshold. Properly harnessed, with file-backed state, execution contracts, and structured natural language harnesses, they perform reliably on production tasks. The error rate has dropped to single-digit percentages on bounded reasoning tasks. The cost has dropped to where economic sense exists for high-volume reasoning.

This means autonomous security operations are now possible. Five years ago they were science fiction.

### 2.3 The harness engineering discipline emerged

A year ago, building production agentic systems was largely improvisational. Each team invented its own approach. Quality varied wildly.

The harness engineering discipline emerged in 2025-2026 from research at Tsinghua (Natural Language Agent Harness paper), Stanford (Meta-Harness optimization work), and Anthropic (effective agents research). The discipline now provides:

- Three-layer separation: backend / runtime charter / NLAH
- Execution contracts as function signatures for agent calls
- File-backed state for cross-context persistence
- Self-evolution with eval gating
- Canonical patterns as composable primitives

Building reliable autonomous systems is now an engineering discipline, not a guess. New entrants can apply this discipline from day one rather than discovering it through painful experience.

### 2.4 The market is structurally underserved in our segments

Wiz, CrowdStrike, Palo Alto are not blind to mid-market hybrid enterprises, manufacturing OT, regulated healthcare, defense contractors. They have made strategic decisions to focus on enterprise cloud-native customers because that segment is most lucrative and most accessible to their product architectures.

These decisions create structural underservice in adjacent segments. The 2025 research shows 74% of mid-market organizations identify cybersecurity as a primary business risk. Manufacturing OT cybersecurity is the third-largest growth impediment for that vertical. Healthcare ransomware is at crisis levels.

These segments need security platforms designed for their constraints. Pure cloud SaaS does not fit. Enterprise-priced products do not fit. Cloud-only architecture does not fit.

The window to address this gap exists because the incumbents are committed to architectural choices that prevent them from quickly addressing it. The window will not stay open forever. A new platform built with the right architectural primitives — edge deployment, mid-market pricing, vertical specialization, autonomous remediation — can establish defensible position before incumbents pivot.

### 2.5 The talent shortage forces force multiplication

ISC2 estimates 4 million unfilled cybersecurity positions globally. CISOs cannot hire their way out of the operational burden.

Force multiplication through technology is no longer optional for security teams. It is the only path forward at industry scale.

Customers are no longer asking "is automation safe?" They are asking "how much can you automate?" The cultural and procurement resistance to autonomy that existed three years ago has dissolved under operational pressure.

### 2.6 These five forces converge

Detection commoditization plus foundation model maturity plus harness engineering plus market underservice plus talent shortage equals the moment.

A new platform designed around the right architectural primitives can build defensible position rapidly. The window is open now. It closes when incumbents pivot or competitors build the same architecture first.

We move now or we lose.

---

## 3. WHO WE BECOME

### 3.1 The five-year horizon

In five years, [Product Name] is the standard autonomous security platform for hybrid enterprises and regulated mid-market organizations globally. We have defined the agentic security operations category. Our runtime charter is referenced in academic research and industry standards. We operate at $100M+ ARR with operations in North America, Europe, and Asia-Pacific.

Our platform serves 1,500+ customers across primary verticals:
- 600+ healthcare organizations from regional hospital systems to national networks
- 300+ manufacturers including critical infrastructure operators
- 250+ financial services organizations from credit unions to regional banks
- 150+ defense contractors and government adjacent organizations
- 200+ technology and SaaS companies

We employ 350+ people across engineering, sales, customer success, threat intelligence, and operations. We operate from primary hubs in [city] (engineering), [city] (sales), and [city] (international).

We have shipped:
- Full multi-cloud detection across AWS, Azure, GCP, OCI
- Tier 1 autonomous remediation across 50+ action classes
- Vertical-specific platforms for healthcare, manufacturing, financial, defense
- Air-gap deployment for classified environments
- International data residency in EU, APAC, regulated US regions
- 200+ pre-built integrations
- A self-evolving agent ecosystem improving continuously through Meta-Harness optimization

We have established:
- SOC 2 Type II, ISO 27001, FedRAMP High certifications
- Vertical compliance leadership (HITRUST, NERC-CIP, FFIEC, IL5)
- A reference customer base in every primary vertical
- Strategic partnerships with major MSSPs for distribution
- A category-defining position in agentic security operations

We face strategic choices about continued independence versus acquisition. Acquisition offers from Microsoft, Google, Palo Alto, CrowdStrike, Cisco have been evaluated and either accepted (if the offer creates more value than continued independence) or declined (if independence creates greater long-term value).

### 3.2 The ten-year horizon

In ten years, [Product Name] is one of the foundational security companies of the agentic era. The runtime charter we built is standard infrastructure for autonomous security systems globally. The multi-agent specialization model is industry common-sense.

We operate at $500M-$1B+ ARR depending on independence vs acquisition path. If independent, we are publicly traded. If acquired, we are the foundation of our acquirer's autonomous security strategy.

Our customer base spans every relevant vertical and geography. Our platform protects critical infrastructure that society depends on: hospitals, power grids, financial systems, defense systems, manufacturing.

We employ thousands of people. We have offices in major cities globally. We have shaped the careers of a generation of security engineers.

We have contributed back to the open-source ecosystem that gave us our foundation. The runtime charter is partially open-sourced. Detection engineering best practices we have developed are publicly available. We have funded academic research in agentic security.

We have weathered the inevitable difficulties: a major incident in a customer environment, a competitive challenge from a well-funded competitor, a regulatory shift that required architectural changes, a talent crisis during industry hiring frenzy. We are still here. Our customers still trust us. Our team still believes in the mission.

### 3.3 What success ultimately means

Financial success — $100M+ ARR, profitable operations, capital efficiency — matters. We will measure it. We will optimize for it.

But financial success alone is not the goal.

The goal is the world described in section 1. Security teams reclaiming time for strategic work. Defenders gaining force multiplication. The economic asymmetry shifting. Critical infrastructure better protected. The next generation of security professionals having tools that make their work effective rather than exhausting.

If we achieve $100M ARR but the world we leave is not meaningfully different than the world we found, we have failed.

If we never reach $100M ARR but the agentic security operations category we helped define becomes the standard way the industry works, we have succeeded.

We aim for both. We refuse to choose one at the expense of the other.

---

## 4. THE CATEGORY WE ARE DEFINING

We are not "another CNAPP." We are not "Wiz with extras." We are not "AI-powered" anything.

We are creating a new category: **Autonomous Security Operations Platform.**

The category is defined by four characteristics:

### 4.1 Continuous autonomous operation

Traditional security platforms are tools that humans operate. Operators run scans, review findings, make decisions, execute remediations, generate reports. The platform is passive infrastructure responding to human direction.

Autonomous Security Operations Platforms operate continuously without human direction within authorized scope. They observe, reason, decide, and act on their own. Humans set strategy, authorize action classes, review high-risk decisions, and intervene when judgment is required. The platform handles operational throughput.

This is a fundamental shift in how security operations work. Tools become teammates.

### 4.2 Multi-agent specialization

Traditional security platforms are monolithic. A single product engine handles detection, correlation, prioritization, alerting. Customization happens through configuration.

Autonomous Security Operations Platforms operate as teams of specialized agents. Each agent has domain expertise. Each agent has bounded responsibility. Specialists coordinate through a supervisor. The overall behavior emerges from specialist interactions, not monolithic logic.

This mirrors how high-performing security organizations operate. The best SOCs have analysts, threat hunters, vulnerability managers, identity engineers, incident responders, compliance specialists. The best autonomous platforms mirror that structure.

### 4.3 Tiered remediation authority

Traditional security platforms either do not remediate (Wiz) or require approval for every action (Palo Alto AgentiX). Both choices fail in production. Detection-only leaves customers buried. Approval-only defeats automation.

Autonomous Security Operations Platforms implement tiered authority. Customer pre-authorizes specific action classes for autonomous execution. Most actions remain approval-gated for safety. High-risk actions remain human-execute-only. Each tier has appropriate safety mechanisms (rollback, blast radius limits, audit).

This matches how high-trust human teams operate. Junior analysts have limited autonomy on routine work. Senior analysts have broader autonomy. Critical decisions go to leadership. Authority matches competence and risk.

### 4.4 Edge mesh deployment

Traditional cloud security platforms are centralized SaaS. The platform sees what cloud APIs expose. It cannot see deeper.

Autonomous Security Operations Platforms deploy at customer edges. They see hybrid environments. They see operational technology. They see medical devices. They see classified enclaves. They operate in air-gapped networks. They span the actual reality of how organizations operate, not the cloud-only abstraction.

This is the only architecture that matches how organizations actually deploy infrastructure.

### 4.5 The category is not us alone

We do not believe we will be the only Autonomous Security Operations Platform. The category will have multiple successful players. We aim to be the leader, not the only one.

What we believe: organizations will adopt platforms with these four characteristics. Organizations who do not will fall behind operationally. The category will become standard.

What we hope: we are the platform that defined the category and shaped how it works.

---

## 5. THE PRINCIPLES THAT GUIDE US

These are not slogans. These are decision-making heuristics for hard moments.

### 5.1 The customer's environment is sacred

Our software runs in customer environments. We have access to their most sensitive systems. We have the ability to make changes to those systems.

This responsibility is sacred. We will not betray it.

In every architectural choice, every product decision, every operational practice, the question is: does this protect the trust customers have placed in us? When the answer is uncertain, we choose conservation over capability.

Concretely:
- We will never take an action a customer has not authorized
- We will never store customer sensitive data we do not need
- We will never use customer data to train models or benefit other customers without explicit consent
- We will never compromise tenant isolation
- We will never silently change behavior without customer awareness

When we make mistakes (and we will), we acknowledge them, document them, and address them. We do not hide.

### 5.2 Truth over comfort

Security is a domain that punishes wishful thinking. Vendors who tell customers what they want to hear lose them when reality hits. We will tell customers truth even when it is uncomfortable.

If our coverage is 80% rather than 100%, we say so.
If a finding is uncertain, we mark it uncertain rather than claiming high confidence.
If our analysis was wrong, we say so and explain.
If we cannot do something a customer asks for, we say so rather than pretending.
If our platform had a problem, we disclose it.

Truth-telling is uncomfortable but it is what differentiates trusted partners from vendors.

### 5.3 Engineering depth, not surface

We could ship faster by cutting corners. We will not.

The runtime charter is the most stable, most carefully designed component. The execution contracts enforce safety. The eval suites validate quality. The audit logs are tamper-evident. The self-evolution is gated.

These are not features that customers see. They are foundations that determine whether the platform fails in production. We invest in foundations because we know the cost of cutting corners in security infrastructure.

When the choice is between shipping a feature faster and getting the foundation right, we get the foundation right.

### 5.4 Specialization wins

The temptation to be "the platform that does everything" is constant. We resist it.

We are not building a SIEM. We are not building EDR. We are not building privileged access management. We are not building DLP for endpoints. We are not building identity providers.

We are building autonomous security operations for cloud and hybrid environments. We do that excellently. We integrate with the rest. We let other platforms be the best at their thing.

Customers buy specialists. Generalists win procurement spreadsheets but lose hearts.

### 5.5 Defenders win when we win

The asymmetry between attackers (low cost to attack, high reward) and defenders (high cost to defend, low recognition for success) has been growing for two decades.

Every architectural choice we make should shift this asymmetry. If a feature makes attacks more expensive without making defense more expensive, ship it. If a feature makes defense cheaper without making attacks cheaper, ship it. If a feature does neither, question whether we should ship it at all.

We are on the defenders' side. We do not pretend to be neutral. We do not provide capabilities that disproportionately help attackers (red-team automation features that have no defensive use; offensive capabilities packaged for "research"). We are unambiguously a defensive technology company.

### 5.6 Long-term over quarterly

Security trust is built over years and lost in moments. We optimize for the long term.

We do not chase quarter-end revenue at the expense of customer fit. We do not deploy features without engineering investment because they look good in a demo. We do not promise things we cannot deliver to win deals. We do not cut corners on security of the platform itself to ship faster.

When the choice is between this quarter's number and our customer's success in two years, we choose the customer's success. The numbers follow.

This is not naive. We will run a financially disciplined company. We will hit growth targets. We will manage cash carefully. But never at the expense of long-term trust.

### 5.7 Build with humility

We are not the smartest team in security. We are not the most experienced. We are not the most capitalized.

We have one advantage: we are willing to do the careful, patient, deep work that a different generation of security platforms requires.

We will make mistakes. We will misunderstand customer needs. We will ship bugs. We will have outages. We will lose deals to better-resourced competitors. We will face challenges we cannot predict.

The teams that win in security are not the smartest. They are the most resilient. They keep learning. They keep iterating. They keep telling the truth. They keep showing up.

We will be that team.

---

## 6. THE PEOPLE WE WANT TO BE

### 6.1 The team we hire

The team we want to build is not assembled by sourcing from the most prestigious companies. It is assembled by sourcing from the values described above and the operational reality below.

We hire people who:

**Have defended.** Built or operated security at scale. Made the calls in 3am incidents. Felt the weight of responsibility. We do not hire from theoretical security backgrounds for positions where defensive operational experience matters.

**Build for production.** Have shipped software that real users depend on. Have been on call. Have debugged the strange and broken things. Have seen what fails in the field. We do not hire from research-only backgrounds for engineering positions.

**Tell the truth.** In interviews, are honest about what they do and do not know. About what they have done well and where they have failed. About why they are leaving their current role. Truth-tellers stay truth-tellers.

**Care about the work.** Are motivated by what we are building, not by the trappings around it. Will work hard because the work matters, not because they are watched. Will tell us when we are wrong because they care more about being right than being agreeable.

**Are humble.** Have been wrong before and remember it. Listen carefully. Update beliefs based on evidence. Do not need to be the smartest person in the room.

**Are kind.** Treat colleagues, customers, candidates with respect. Push hard on ideas; never on people. Build others up rather than tearing them down.

We hire slowly. We fire quickly when patterns emerge that violate these principles. We protect the team we have built.

### 6.2 The leaders we want to become

The founding team commits to becoming the leaders this company needs. Not the leaders we are when we start.

This means:
- Continuous learning about what we do not know
- Continuous self-assessment about how we are doing
- Continuous willingness to step back from roles when better leaders are needed
- Continuous investment in the team's growth, not just the company's growth

We will make decisions that surprise people. We will hire executives more experienced than we are when the company outgrows our individual capabilities. We will sometimes step away from leadership roles in our own company because that is what the company needs.

The company is bigger than any of us. Our job is to serve it.

### 6.3 The culture we want to live in

We want to work in a place where people are honest with each other, kind to each other, and genuinely engaged with the work. Where the best ideas win regardless of who proposes them. Where mistakes are learning opportunities, not career-ending events. Where customers are treated as partners, not transactions. Where the work matters and people know why.

This is not a "fun" culture. We will not have foosball tables and unlimited PTO theater and wellness programs that mask burnout. We will be direct. We will work hard. We will sometimes have hard conversations.

But we will also have a culture where:
- Every person knows what we are building and why
- Every person has work that matters
- Every person can disagree with leadership without career consequence
- Every person sees their colleagues as colleagues, not competitors
- Every person feels their work is recognized and valued

This is a high-trust, high-performance culture. It requires constant tending. We commit to tending it.

---

## 7. THE OUTCOMES WE COMMIT TO

### 7.1 To customers

We commit to:
- Telling you the truth about our product, including its limitations
- Investing in your success, not just your contract renewal
- Protecting your data with our best capabilities, not minimum compliance
- Disclosing problems quickly and clearly
- Working to deserve your trust every day

If we fail you, we acknowledge it, fix it, and learn from it. We do not hide.

### 7.2 To investors

We commit to:
- Honest reporting of progress and challenges
- Disciplined capital allocation toward long-term value
- Transparency about how the business is performing
- Building toward outcomes that justify your trust
- Optimizing for your success and ours together

We do not promise outcomes we cannot deliver. We do not hide problems. We do not optimize for our outcomes at your expense.

### 7.3 To the team

We commit to:
- Compensation that reflects market reality and individual contribution
- Equity that meaningfully participates in success
- Honest feedback about performance and growth
- Investment in your career, not just your role
- Work that matters and recognition for doing it well
- A culture of trust, kindness, and high performance

If you outgrow us, we help you find what comes next. If we make decisions that affect you, we tell you why. If we fail you as employers, we acknowledge it and try to do better.

### 7.4 To the industry

We commit to:
- Contributing back to the open-source ecosystem we build on
- Sharing learnings publicly through writing, talks, research
- Funding research that advances the field
- Mentoring the next generation of security engineers
- Acting as a credit to the industry, not a stain

We are part of a community. We act like it.

---

## 8. THE RISKS WE FACE

Honesty about what could prevent us from achieving this vision.

### 8.1 We could be wrong about market timing

Maybe customers are not ready for autonomous security. Maybe edge deployment is a phantom need. Maybe mid-market security spending will not grow as projected.

We mitigate by validating early through customer discovery and shipping conservatively. We accept that some risk remains.

### 8.2 We could be outpaced by better-funded competitors

Wiz could pivot to edge. Microsoft could integrate Defender for Cloud with their AI. Google could push Wiz into autonomous remediation. CrowdStrike could acquire a runtime charter team.

We mitigate by moving fast in our specific verticals, building deep customer relationships, and creating switching costs through customization and integration.

### 8.3 We could fail at execution

Security infrastructure software is hard. Multi-agent systems are hard. Production-grade reliability is hard. Customer-grade quality is hard.

We mitigate by hiring the right people, building disciplined engineering practices, and accepting longer timelines than enthusiastic projections.

### 8.4 We could face an existential incident

A platform-wide security breach. A major customer outage caused by our autonomous remediation. A regulatory action against agentic security platforms. A black swan we did not predict.

We mitigate through defensive depth in product, operations, and team. Some risk remains.

### 8.5 We could lose our way

Founders distracted by visibility instead of focused on customers. Team growth that dilutes culture. Pressure that compromises principles. Success that breeds complacency.

We mitigate through our principles and through commitment to remember why we started.

---

## 9. THE COMMITMENT WE MAKE

We commit to building this company. To serving these customers. To shipping this platform. To holding to these principles. To becoming this team.

We commit to honesty about what we do not know. To resilience when things go wrong. To excellence in the work. To kindness toward colleagues, customers, candidates. To long-term thinking when short-term temptation arises.

We commit to building a security company that defenders deserve. A company that does the patient, careful, deep work that this domain requires. A company that earns trust over years through actions, not claims.

We commit to remembering, when we are tempted to take shortcuts, why we started: because security teams deserve better tools. Because defenders deserve force multiplication. Because critical infrastructure deserves protection. Because the world we want to live in requires this work to be done.

This is the vision. This is the commitment. This is where we are going.

---

## DOCUMENT ENDS

The PRD says what we are building. This document says why and where it leads. Together they should answer most strategic questions.

When you face a hard decision, ask: does this serve the vision? Does this honor the principles? Does this match the commitment?

If yes, proceed. If no, reconsider.

This document evolves. It will be revised annually. The destination shifts as we learn. The principles do not.

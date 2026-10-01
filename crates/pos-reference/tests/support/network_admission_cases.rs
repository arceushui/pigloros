// Public admission composition using the independently signed fixture above.
use pos_reference::sandbox_provider_protocol::{
    LocalNetworkAdmission, NetworkProxyLimits, NetworkRetentionPolicy,
};

struct LocalBindingFixture {
    grant: AuthenticatedAdmissionGrant,
    commitment: SelectorGrantCommitment,
    policy: Vec<u8>,
    plans: Vec<NetworkExchangePlan>,
}

impl LocalBindingFixture {
    fn new(
        mode: u8,
        capabilities: Vec<Value>,
        plans: Vec<NetworkExchangePlan>,
        proxy_limits: [u64; 3],
    ) -> TestResult<Self> {
        let mut fixture = Fixture::new()?;
        let mut limits = commitment_limit_values();
        for (offset, value) in proxy_limits.into_iter().enumerate() {
            limits[10 + offset] =
                Value::Array(vec![integer(10 + u64::try_from(offset)?), integer(value)]);
        }
        let policy =
            launch_policy_with_limits(wrapped_digest(&fixture.sim1)?, u64::from(mode), limits)?;
        fixture.lps1 =
            redigest_unsigned_field(&policy, "LPS1", 6, Value::Array(ordered(capabilities)?))?;
        fixture.policy = fixture.policy_for_image(&fixture.sim1, &fixture.lps1)?;
        let provider = fixture.admit()?;
        let image =
            provider.admit_image(&fixture.sim1, &fixture.root_image, &fixture.executable)?;
        let launch = provider.admit_launch_policy(&fixture.lps1, &image)?;
        let request = execute_request(&fixture, &launch, &["execute"])?;
        let request = redigest_unsigned_field(
            &request,
            "SPX1",
            21,
            Value::Array(plans.iter().map(local_plan_value).collect()),
        )?;
        let request = SandboxExecuteRequest::from_canonical_cbor(&request)?;
        let mut attempt = selector_attempt();
        attempt.mode = mode;
        attempt.network_allowed = mode == 0;
        let commitment = provider.derive_selector_grant_commitment(
            &image,
            &launch,
            &fixture.evaluation_request(&launch)?,
            &attempt,
            &plans,
        )?;
        let grant = admission_grant(&fixture, &request, &launch, &commitment)?;
        let grant = resign_unsigned_field(
            &grant,
            "AGR1",
            22,
            Value::Array(plans.iter().map(|plan| bytes(plan.plan_digest)).collect()),
            &fixture.authority.runtime,
        )?;
        let grant = provider.authenticate_grant(&grant, &request, &image, &launch, &commitment)?;
        Ok(Self {
            grant,
            commitment,
            policy: fixture.lps1,
            plans,
        })
    }

    fn bind(
        &self,
    ) -> Result<
        LocalNetworkAdmission,
        pos_reference::sandbox_provider_protocol::SandboxProviderProtocolError,
    > {
        self.grant
            .bind_local_network(&self.commitment, &self.policy, &self.plans)
    }
}

#[test]
fn local_network_binds_ordered_occurrences_endpoints_grant_and_limits() -> TestResult {
    for address in [vec![127, 0, 0, 1], vec![1; 16]] {
        let fixture = LocalBindingFixture::new(
            0,
            vec![local_endpoint(&address, 443, 12, 34)],
            vec![local_plan(0, 3, 4)?, local_plan(1, 3, 4)?],
            [11, 22, 33],
        )?;
        let admission = fixture.bind()?;
        assert_eq!(admission.grant(), &fixture.grant);
        assert_eq!(admission.grant().attempt_id, [33; 16]);
        assert_eq!(
            admission.limits(),
            NetworkProxyLimits {
                request_bytes: 11,
                response_bytes: 22,
                milliseconds: 33
            }
        );
        assert_eq!(admission.exchanges().len(), 2);
        for ((plan, endpoint), expected) in admission.exchanges().zip(&fixture.plans) {
            assert_eq!(plan, expected);
            assert_eq!(endpoint.capability_id, "execute");
            assert_eq!(endpoint.address, address);
            assert_eq!(endpoint.destination_port, 443);
            assert_eq!(endpoint.request_maximum, 12);
            assert_eq!(endpoint.response_maximum, 34);
        }
    }
    Ok(())
}

#[test]
fn local_network_rejects_nonlocal_foreign_and_noncanonical_policy() -> TestResult {
    for mode in [1, 2, 3] {
        let fixture = LocalBindingFixture::new(mode, vec![], vec![], [1; 3])?;
        assert!(fixture.bind().is_err());
    }
    let fixture = LocalBindingFixture::new(0, vec![], vec![], [1; 3])?;
    assert_eq!(fixture.bind()?.exchanges().len(), 0);
    let changed = redigest_unsigned_field(
        &fixture.policy,
        "LPS1",
        2,
        Value::Text("foreign".to_owned()),
    )?;
    for policy in [changed, vec![], vec![255]] {
        assert!(fixture
            .grant
            .bind_local_network(&fixture.commitment, &policy, &fixture.plans)
            .is_err());
    }
    let foreign = LocalBindingFixture::new(0, vec![], vec![], [2; 3])?;
    assert!(fixture
        .grant
        .bind_local_network(&foreign.commitment, &fixture.policy, &fixture.plans)
        .is_err());
    Ok(())
}

#[test]
fn local_network_rejects_plan_reordering_omission_substitution_and_oversized_lists() -> TestResult {
    let fixture = LocalBindingFixture::new(
        0,
        vec![local_endpoint(&[127, 0, 0, 1], 443, 10, 10)],
        vec![local_plan(0, 3, 4)?, local_plan(1, 3, 4)?],
        [100; 3],
    )?;
    let mut reordered = fixture.plans.clone();
    reordered.reverse();
    let mut corrupt = fixture.plans.clone();
    corrupt[0].plan_digest[0] ^= 1;
    let mut substituted = fixture.plans.clone();
    substituted[0].request_digest = [99; 32];
    seal_local_plan(&mut substituted[0])?;
    let mut wrong_id = fixture.plans.clone();
    wrong_id[0].capability_id = "bad id".to_owned();
    seal_local_plan(&mut wrong_id[0])?;
    for plans in [
        vec![],
        fixture.plans[..1].to_vec(),
        reordered,
        corrupt,
        substituted,
        wrong_id,
        vec![fixture.plans[0].clone(); 257],
    ] {
        assert!(fixture
            .grant
            .bind_local_network(&fixture.commitment, &fixture.policy, &plans)
            .is_err());
    }
    Ok(())
}

#[test]
fn local_network_requires_unique_matching_bounded_endpoint_capabilities() -> TestResult {
    let endpoint = local_endpoint(&[127, 0, 0, 1], 443, 10, 10);
    let duplicate = local_endpoint(&[127, 0, 0, 1], 444, 10, 10);
    for capabilities in [vec![], vec![endpoint.clone(), duplicate]] {
        let fixture =
            LocalBindingFixture::new(0, capabilities, vec![local_plan(0, 3, 4)?], [100; 3])?;
        assert!(fixture.bind().is_err());
    }
    for plan in [local_plan(0, 11, 4)?, local_plan(0, 3, 11)?] {
        let fixture = LocalBindingFixture::new(0, vec![endpoint.clone()], vec![plan], [100; 3])?;
        assert!(fixture.bind().is_err());
    }
    let fixture =
        LocalBindingFixture::new(0, vec![endpoint], vec![local_plan(0, 10, 10)?], [100; 3])?;
    assert_eq!(fixture.bind()?.exchanges().len(), 1);
    Ok(())
}

#[test]
fn local_network_rejects_unsupported_retention_and_unrepresentable_request_frames() -> TestResult {
    let mut unsupported = local_plan(0, 1, 1)?;
    unsupported.retention_policy_digest = [99; 32];
    seal_local_plan(&mut unsupported)?;
    for plan in [unsupported, local_plan(0, 16 * 1024 * 1024, 1)?] {
        let fixture = LocalBindingFixture::new(
            0,
            vec![local_endpoint(&[127, 0, 0, 1], 443, 128 * 1024 * 1024, 10)],
            vec![plan],
            [100; 3],
        )?;
        assert!(fixture.bind().is_err());
    }
    Ok(())
}

#[test]
fn local_network_retains_literal_zero_limits_without_minting_runtime_authority() -> TestResult {
    let fixture = LocalBindingFixture::new(
        0,
        vec![local_endpoint(&[127, 0, 0, 1], 443, 10, 10)],
        vec![local_plan(0, 3, 4)?],
        [0; 3],
    )?;
    let admission = fixture.bind()?;
    assert_eq!(
        admission.limits(),
        NetworkProxyLimits {
            request_bytes: 0,
            response_bytes: 0,
            milliseconds: 0
        }
    );
    // Returned limits are a snapshot; caller edits cannot alter retained ceilings.
    let mut snapshot = admission.limits();
    snapshot.request_bytes = 999;
    assert_ne!(snapshot, admission.limits());
    assert_eq!(
        admission.grant().elm1_digest,
        fixture.commitment.effective_limits_digest()
    );
    Ok(())
}

fn local_endpoint(address: &[u8], port: u64, request: u64, response: u64) -> Value {
    Value::Array(vec![
        Value::Text("execute".to_owned()),
        integer(0),
        integer(u64::from(address.len() != 4)),
        Value::Bytes(address.to_vec()),
        integer(port),
        integer(request),
        integer(response),
    ])
}

fn local_plan(
    occurrence: u64,
    request_length: u64,
    response_maximum: u64,
) -> TestResult<NetworkExchangePlan> {
    let mut plan = network_exchange_plan()?;
    plan.occurrence = occurrence;
    plan.request_length = request_length;
    plan.response_maximum = response_maximum;
    plan.retention_policy_digest = NetworkRetentionPolicy::RetainIndefinitely.digest()?;
    seal_local_plan(&mut plan)?;
    Ok(plan)
}

fn seal_local_plan(plan: &mut NetworkExchangePlan) -> TestResult {
    let Value::Array(mut fields) = local_plan_value(plan) else {
        return Err("plan must be an array".into());
    };
    fields.truncate(10);
    plan.plan_digest = digest_value(b"PiglorOS.NetworkExchangePlan.v1\0", &Value::Array(fields))?;
    Ok(())
}

fn local_plan_value(plan: &NetworkExchangePlan) -> Value {
    Value::Array(vec![
        Value::Text("NXP1".to_owned()),
        integer(1),
        Value::Bytes(plan.exchange_id.to_vec()),
        integer(plan.occurrence),
        Value::Text(plan.capability_id.clone()),
        integer(plan.request_length),
        bytes(plan.request_digest),
        integer(plan.response_maximum),
        bytes(plan.expected_response_digest),
        bytes(plan.retention_policy_digest),
        bytes(plan.plan_digest),
    ])
}

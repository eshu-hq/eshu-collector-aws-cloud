// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package bedrock

import (
	"context"
)

// fakeClient is a static Bedrock Client double. Each List returns its seeded
// slice (or seeded error) so scanner tests exercise resource and relationship
// emission without any AWS SDK dependency.
type fakeClient struct {
	foundationModels  []FoundationModel
	customModels      []CustomModel
	customizationJobs []ModelCustomizationJob
	provisionedModels []ProvisionedModelThroughput
	guardrails        []Guardrail
	agents            []Agent
	actionGroups      []AgentActionGroup
	knowledgeBases    []KnowledgeBase
	guardrailErr      error
}

func (f *fakeClient) ListFoundationModels(context.Context) ([]FoundationModel, error) {
	return f.foundationModels, nil
}

func (f *fakeClient) ListCustomModels(context.Context) ([]CustomModel, error) {
	return f.customModels, nil
}

func (f *fakeClient) ListModelCustomizationJobs(context.Context) ([]ModelCustomizationJob, error) {
	return f.customizationJobs, nil
}

func (f *fakeClient) ListProvisionedModelThroughputs(context.Context) ([]ProvisionedModelThroughput, error) {
	return f.provisionedModels, nil
}

func (f *fakeClient) ListGuardrails(context.Context) ([]Guardrail, error) {
	return f.guardrails, f.guardrailErr
}

func (f *fakeClient) ListAgents(context.Context) ([]Agent, error) {
	return f.agents, nil
}

func (f *fakeClient) ListAgentActionGroups(context.Context) ([]AgentActionGroup, error) {
	return f.actionGroups, nil
}

func (f *fakeClient) ListKnowledgeBases(context.Context) ([]KnowledgeBase, error) {
	return f.knowledgeBases, nil
}

var _ Client = (*fakeClient)(nil)

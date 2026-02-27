'use strict';

const fs = require('fs');
const path = require('path');
const Ajv = require('ajv');

const ajv = new Ajv({ allErrors: true, allowUnionTypes: true });

function loadSchema(schemaPath) {
  const raw = fs.readFileSync(schemaPath, 'utf8');
  return JSON.parse(raw);
}

function loadRegistry(registryPath, schemaPath) {
  const resolvedRegistryPath = path.resolve(registryPath);
  const resolvedSchemaPath = path.resolve(schemaPath);
  const schema = loadSchema(resolvedSchemaPath);
  const validate = ajv.compile(schema);
  const registry = JSON.parse(fs.readFileSync(resolvedRegistryPath, 'utf8'));
  const ok = validate(registry);
  if (!ok) {
    const error = new Error('invalid_model_registry');
    error.details = validate.errors;
    throw error;
  }
  return registry;
}

function findModel(registry, modelId) {
  return registry.models.find((model) => model.model_id === modelId);
}

function resolveRoutingRule(registry, params) {
  const { division, capability, task_type, risk_tier } = params;
  return registry.routing_rules.find((rule) => {
    if (rule.division && rule.division !== division) return false;
    if (rule.capability && rule.capability !== capability) return false;
    if (rule.task_type && rule.task_type !== task_type) return false;
    if (rule.risk_tier && rule.risk_tier !== risk_tier) return false;
    return true;
  });
}

function resolveModelForRequest(registry, params) {
  const { division, task_type } = params;
  const rule = resolveRoutingRule(registry, params);
  if (rule) {
    return { model_id: rule.model_id, lane: rule.lane_type || 'primary', source: 'routing_rule' };
  }

  const assignment = registry.division_assignments[division];
  if (assignment) {
    const wantsSpecialist = Array.isArray(assignment.specialist_tasks)
      && task_type
      && assignment.specialist_tasks.includes(task_type)
      && assignment.specialist;
    if (wantsSpecialist) {
      return { model_id: assignment.specialist, lane: 'specialist', source: 'division_specialist' };
    }
    return { model_id: assignment.primary, lane: 'primary', source: 'division_primary' };
  }

  return {
    model_id: registry.fallback.default_model,
    lane: registry.fallback.default_lane || 'primary',
    source: 'fallback'
  };
}

module.exports = {
  loadRegistry,
  findModel,
  resolveModelForRequest
};

const { generateSync, createGuardrails } = require('otplib');

const GUARDRAILS = createGuardrails({ MIN_SECRET_BYTES: 1 });

function generateToken(secret, epoch, digits = 6, period = 30) {
  try {
    return generateSync({
      secret,
      guardrails: GUARDRAILS,
      digits,
      step: period,
      ...(epoch !== undefined && { epoch }),
    });
  } catch {
    return null;
  }
}

module.exports = { generateToken };

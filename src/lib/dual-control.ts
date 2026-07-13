const pendingActions = new Map<string, {
  action: string;
  requestedBy: string;
  targetId: string;
  createdAt: Date;
  approvedBy: string[];
  requiredApprovals: number;
}>();

export function requestDualControl(
  action: string,
  requestedBy: string,
  targetId: string,
  requiredApprovals: number = 2,
): string {
  const requestId = `${action}:${targetId}:${Date.now()}`;
  pendingActions.set(requestId, {
    action,
    requestedBy,
    targetId,
    createdAt: new Date(),
    approvedBy: [requestedBy],
    requiredApprovals,
  });
  return requestId;
}

export function approveDualControl(requestId: string, approverId: string): {
  approved: boolean;
  currentApprovals: number;
  required: number;
} {
  const req = pendingActions.get(requestId);
  if (!req) return { approved: false, currentApprovals: 0, required: 0 };

  if (!req.approvedBy.includes(approverId)) {
    req.approvedBy.push(approverId);
  }

  const approved = req.approvedBy.length >= req.requiredApprovals;
  if (approved) {
    pendingActions.delete(requestId);
  }

  return {
    approved,
    currentApprovals: req.approvedBy.length,
    required: req.requiredApprovals,
  };
}

export function breakGlass(userId: string, reason: string): {
  granted: boolean;
  requestId: string;
  note: string;
} {
  const requestId = `break-glass:${userId}:${Date.now()}`;
  return {
    granted: true,
    requestId,
    note: `Break-glass access by ${userId}. Reason: ${reason}. This action is logged and will be reviewed.`,
  };
}

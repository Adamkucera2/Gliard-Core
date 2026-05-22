# Core Scanners (Always present in all editions)
try:
    from .security import (
        SecretScanner, 
        PromptScanner, 
        ToolScanner, 
        SensitiveLoggingScanner
    )
except ImportError:
    pass

try:
    from .ai_agent import (
        HallucinationScanner,
        LogicScanner
    )
except ImportError:
    pass

# Guard Scanners (May be absent in Core edition)
try:
    from .security_premium import (
        DependencyScanner,
        ContainerAuditor
    )
    from .ai_agent_premium import (
        DataFlowScanner,
        ReasoningAuditor,
        BudgetScanner,
        PrivacyAuditor,
    )
    from .logic import MemoryAuditor
    from .eu_compliance import (
        EUAIActRiskClassificationScanner,
        EUAIActTransparencyScanner,
        EUAIActHumanOversightScanner,
        EUAIActLoggingScanner,
        EUAIActDataGovernanceScanner,
    )
    from .mcp import MCPConfigScanner
except ImportError:
    pass

# Sentinel Scanners (Only in Sentinel edition)
try:
    from ..sentinel.adversary import AdversaryScanner
except ImportError:
    # This is expected in Core and Guard editions
    pass

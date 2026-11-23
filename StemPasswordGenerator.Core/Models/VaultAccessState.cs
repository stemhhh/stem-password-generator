namespace StemPasswordGenerator.Models;

public enum VaultAccessState
{
    Locked = 0,
    PendingHumanVerification = 1,
    Unlocked = 2
}

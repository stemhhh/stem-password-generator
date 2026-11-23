namespace StemPasswordGenerator.Services;

public readonly record struct Argon2Profile(int MemoryKiB, int Iterations, int Parallelism)
{
    public const int MinimumMemoryKiB = 8 * 1024;
    public const int MaximumMemoryKiB = 64 * 1024;

    public static Argon2Profile Current { get; private set; } = Detect();

    public static Argon2Profile Detect() => Create(EstimateAvailableRamGb(), Environment.ProcessorCount);

    public static Argon2Profile Create(double ramGb, int cores)
    {
        cores = Math.Max(1, cores);
        var memoryKiB = ramGb switch
        {
            < 3 => 16 * 1024,
            < 4 => 24 * 1024,
            < 8 => 32 * 1024,
            _ => 48 * 1024
        };

        var iterations = 3;
        var parallelism = ramGb < 4
            ? 1
            : Math.Clamp(cores / 2, 1, 2);

        return new Argon2Profile(memoryKiB, iterations, parallelism);
    }

    public static void Use(Argon2Profile profile)
    {
        Current = new Argon2Profile(
            Math.Clamp(profile.MemoryKiB, MinimumMemoryKiB, MaximumMemoryKiB),
            Math.Clamp(profile.Iterations, 1, 4),
            Math.Clamp(profile.Parallelism, 1, 8));
    }

    public static void ResetToMachine() => Current = Detect();

    internal static double EstimateAvailableRamGb()
    {
        var available = GC.GetGCMemoryInfo().TotalAvailableMemoryBytes;
        if (available <= 0)
        {
            return 8;
        }

        return available / (1024d * 1024d * 1024d);
    }
}

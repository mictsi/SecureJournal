using System.Text;
using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;

namespace SecureJournal.Web.Infrastructure.Logging;

internal sealed record FileLoggingSettings(bool Enabled, string Path, LogLevel MinimumLevel)
{
    public static FileLoggingSettings FromConfiguration(IConfiguration configuration)
    {
        var enabled = bool.TryParse(configuration["Logging:File:Enabled"], out var parsedEnabled) && parsedEnabled;
        var path = configuration["Logging:File:Path"];
        var minLevelText = configuration["Logging:File:MinimumLevel"];
        var minLevel = Enum.TryParse<LogLevel>(minLevelText, ignoreCase: true, out var parsedLevel)
            ? parsedLevel
            : LogLevel.Information;

        return new FileLoggingSettings(
            Enabled: enabled,
            Path: string.IsNullOrWhiteSpace(path) ? "logs/securejournal.log" : path.Trim(),
            MinimumLevel: minLevel);
    }
}

internal sealed class SimpleFileLoggerProvider : ILoggerProvider
{
    private readonly string _filePath;
    private readonly LogLevel _minimumLevel;
    private readonly object _sync = new();
    private readonly ConcurrentQueue<string> _pendingLines = new();
    private readonly Timer _flushTimer;
    private StreamWriter? _writer;
    private bool _disposed;
    private int _queuedCount;
    private int _flushInProgress;

    public SimpleFileLoggerProvider(string contentRootPath, FileLoggingSettings settings)
    {
        _minimumLevel = settings.MinimumLevel;
        _filePath = System.IO.Path.IsPathRooted(settings.Path)
            ? settings.Path
            : System.IO.Path.Combine(contentRootPath, settings.Path);

        var directory = System.IO.Path.GetDirectoryName(_filePath);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        _writer = new StreamWriter(new FileStream(_filePath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite))
        {
            AutoFlush = false
        };

        _flushTimer = new Timer(_ => FlushBufferedLinesSafe(), null, dueTime: 500, period: 500);
    }

    public ILogger CreateLogger(string categoryName) => new SimpleFileLogger(this, categoryName);

    public bool IsEnabled(LogLevel logLevel) => logLevel != LogLevel.None && logLevel >= _minimumLevel;

    public void WriteLine(string categoryName, LogLevel logLevel, EventId eventId, string message, Exception? exception)
    {
        if (!IsEnabled(logLevel) || _disposed)
        {
            return;
        }

        var sb = new StringBuilder(256);
        sb.Append(DateTimeOffset.UtcNow.ToString("yyyy-MM-dd HH:mm:ss.fff 'UTC'"));
        sb.Append(" [");
        sb.Append(logLevel);
        sb.Append("] ");
        sb.Append(categoryName);
        if (eventId.Id != 0 || !string.IsNullOrWhiteSpace(eventId.Name))
        {
            sb.Append(" (");
            sb.Append(eventId.Id);
            if (!string.IsNullOrWhiteSpace(eventId.Name))
            {
                sb.Append(':');
                sb.Append(eventId.Name);
            }
            sb.Append(')');
        }

        sb.Append(": ");
        sb.Append(message);

        if (exception is not null)
        {
            sb.AppendLine();
            sb.Append(exception);
        }

        _pendingLines.Enqueue(sb.ToString());
        var queued = Interlocked.Increment(ref _queuedCount);

        // Flush sooner under bursts to keep memory bounded.
        if (queued >= 128)
        {
            FlushBufferedLinesSafe();
        }
    }

    public void Dispose()
    {
        _flushTimer.Dispose();
        FlushBufferedLinesSafe();

        lock (_sync)
        {
            _disposed = true;
            _writer?.Flush();
            _writer?.Dispose();
            _writer = null;
        }
    }

    private void FlushBufferedLinesSafe()
    {
        if (_disposed)
        {
            return;
        }

        if (Interlocked.Exchange(ref _flushInProgress, 1) == 1)
        {
            return;
        }

        try
        {
            lock (_sync)
            {
                if (_writer is null)
                {
                    while (_pendingLines.TryDequeue(out _))
                    {
                        Interlocked.Decrement(ref _queuedCount);
                    }

                    return;
                }

                while (_pendingLines.TryDequeue(out var line))
                {
                    _writer.WriteLine(line);
                    Interlocked.Decrement(ref _queuedCount);
                }

                _writer.Flush();
            }
        }
        catch
        {
            // Never let logging failures crash the app.
        }
        finally
        {
            Interlocked.Exchange(ref _flushInProgress, 0);
        }
    }

    private sealed class SimpleFileLogger : ILogger
    {
        private readonly SimpleFileLoggerProvider _provider;
        private readonly string _categoryName;

        public SimpleFileLogger(SimpleFileLoggerProvider provider, string categoryName)
        {
            _provider = provider;
            _categoryName = categoryName;
        }

        public IDisposable BeginScope<TState>(TState state) where TState : notnull => NullScope.Instance;

        public bool IsEnabled(LogLevel logLevel) => _provider.IsEnabled(logLevel);

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (!IsEnabled(logLevel))
            {
                return;
            }

            var message = formatter(state, exception);
            if (string.IsNullOrWhiteSpace(message) && exception is null)
            {
                return;
            }

            _provider.WriteLine(_categoryName, logLevel, eventId, message, exception);
        }
    }

    private sealed class NullScope : IDisposable
    {
        public static readonly NullScope Instance = new();
        public void Dispose() { }
    }
}

class JobProgressManager {
    static [JobProgressManager] $instance
    JobProgressManager() {
        if ($null -ne [JobProgressManager]::instance) {
            Throw "JobProgressManager is a singleton class. Use [JobProgressManager]::GetInstance() to get the single instance."
        }
    }

    static [JobProgressManager] GetInstance() {
        if ($null -eq [JobProgressManager]::instance) {
            [JobProgressManager]::instance = [JobProgressManager]::new()
        }
        return [JobProgressManager]::instance
    }

    static [void] SetInstance([JobProgressManager]$mgr) {
        if ($null -eq [JobProgressManager]::instance) {
            [JobProgressManager]::instance = $mgr
        }
        elseif (-not [object]::ReferenceEquals($mgr, [JobProgressManager]::instance)) {
            Throw "JobProgressManager instance already set. Cannot change instance."
        }
    }

    # Key: JobId, Value: Channel[Hashtable]
    [System.Collections.Concurrent.ConcurrentDictionary[int, System.Threading.Channels.Channel[Hashtable]]]$channels =
        [System.Collections.Concurrent.ConcurrentDictionary[int, System.Threading.Channels.Channel[Hashtable]]]::new()

    # Write the progress message to a channel for the current thread
    [void] WriteJobProgress([Hashtable]$progress) {
        # Ensure channel exists for this thread
        $channel = [JobProgressManager]::GetInstance().channels.GetOrAdd($progress.Id, {
            param($k)
            [System.Threading.Channels.Channel]::CreateUnbounded[Hashtable]()
        })

        # Send progress message
        $channel.Writer.WriteAsync($progress, [Threading.CancellationToken]::None)
            # .AsTask().Wait()

        # Complete channel if job is done
        if ($progress.PercentComplete -ge 100) {
            $channel.Writer.Complete()
        }
    }

    # Processes progress messages from all threads and render them with Write-Progress
    [void] ProcessProgress() {
        $inst = [JobProgressManager]::GetInstance()
        foreach ($threadId in $inst.channels.Keys) {
            $channel = $inst.channels[$threadId]

            # Drain available progress messages
            $progress = $null
            while ($channel.Reader.TryRead([ref]$progress)) {
                # Not Write-Progress because Pester has trouble mocking it
                Write-ProgressMockable $progress
            }
            # Remove completed channels
            if ($channel.Reader.Completion.IsCompleted) {
                [void]$inst.channels.TryRemove($threadId, [ref]$null)
            }
        }
    }
}

# Pass-through to Write-Progress, for use inside jobs. Satisfies Pester's difficulties mocking Write-Progress directly.
Function Write-ProgressMockable {
    param (
        [Hashtable]$SplattedParams
    )
    Write-Progress @SplattedParams
}

Function Write-JobProgress {
    param (
        [Parameter(Mandatory=$true)][string]$Activity,
        [string]$Status,
        [int]$PercentComplete = 0,
        [string]$CurrentOperation
    )
    [JobProgressManager]::GetInstance().WriteJobProgress(@{
        Activity = $Activity
        Status = $Status
        PercentComplete = $PercentComplete
        CurrentOperation = $CurrentOperation
        Id = [System.Threading.Thread]::CurrentThread.ManagedThreadId
    })
}

# Register type accelerator for JobProgressManager
# Must be run after the class is defined
$ta = [PSObject].Assembly.GetType('System.Management.Automation.TypeAccelerators')
$ta::Add('JobProgressManager', [JobProgressManager])




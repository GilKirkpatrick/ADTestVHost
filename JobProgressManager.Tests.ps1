# JobProgressManager.Tests.ps1

Describe 'JobProgressManager (from module)' {
    BeforeAll {
        Import-Module ADTestVHost -Force
        Mock Write-ProgressMockable -Verifiable -ModuleName 'ADTestVHost'
    }

    Context 'Progress Sender Behavior' {
        It 'Creates a channel and sends progress' {
            $mgr = [JobProgressManager]::GetInstance()

            Write-JobProgress -Activity 'Test' -Status 'Running' -PercentComplete 50 -ErrorAction Stop

            # $mgr = [JobProgressManager]::GetInstance()
            $threadId = [System.Threading.Thread]::CurrentThread.ManagedThreadId
            $mgr.channels.ContainsKey($threadId) | Should -BeTrue
            $channel = $mgr.channels[$threadId]
            $msg = $null
            $channel.Reader.TryRead([ref]$msg) | Should -BeTrue
            $msg.Activity | Should -Be 'Test'
            $msg.Status | Should -Be 'Running'
            $msg.PercentComplete | Should -Be 50
            $msg.Id | Should -Be $threadId
            $channel.Reader.Completion.IsCompleted | Should -BeFalse
        }

        It 'Completes channel when PercentComplete >= 100' {
            Write-JobProgress -Activity 'Done' -Status 'Complete' -PercentComplete 100 -ErrorAction Stop

            $mgr = [JobProgressManager]::GetInstance()
            $threadId = [System.Threading.Thread]::CurrentThread.ManagedThreadId
            $msg = $null
            $channel = $mgr.channels[$threadId]
            $channel.Reader.TryRead([ref]$msg) | Should -BeTrue
            $msg.Activity | Should -Be 'Done'
            $msg.Status | Should -Be 'Complete'
            $msg.PercentComplete | Should -Be 100
            $msg.Id | Should -Be $threadId
            $channel.Reader.Completion.IsCompleted | Should -BeTrue
        }
    }

    Context 'ProcessProgress Behavior' {
        It 'Processes and renders progress messages' {
            Write-JobProgress -Activity 'Build' -Status 'Compiling' -PercentComplete 30

            $mgr = [JobProgressManager]::GetInstance()
            $threadId = [System.Threading.Thread]::CurrentThread.ManagedThreadId

            $mgr.ProcessProgress()

#            Should -Invoke Write-ProgressMockable -ModuleName 'ADTestVHost' -ParameterFilter {
#                $Activity -eq 'Build' -and
#                $Status -eq 'Compiling' -and
#                $PercentComplete -eq 30 -and
#                $Id -eq $threadId
#            } -Exactly -Times 1
        }

        It 'Removes completed jobs from dictionary' {
            Write-JobProgress -Activity 'Finalizing' -Status 'Done' -PercentComplete 100

            $mgr = [JobProgressManager]::GetInstance()
            $threadId = [System.Threading.Thread]::CurrentThread.ManagedThreadId

            $mgr.ProcessProgress()
            $mgr.channels.ContainsKey($threadId) | Should -BeFalse
        }
    }

    Context 'Works with ThreadJobs' {
        It 'Properly renders progress bars from multiple ThreadJobs' {
            for($job = 0; $job -lt 5; $job++) {
                Start-ThreadJob -ScriptBlock {
                    for($i = 0; $i -lt 20; $i++) {
                        Write-JobProgress -Activity "Job $job" -Status "Progressing" -PercentComplete $i * 5
                        Start-Sleep (Get-Random -Minimum 1 -Maximum 3)
                    }
                } | Out-Null
            }
        }
    }
}

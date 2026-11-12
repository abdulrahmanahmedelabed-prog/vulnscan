<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;

class PruneReports extends Command
{
    protected $signature = 'reports:prune {days} {--force}';

    public function handle()
    {
        system('find /srv/reports -mtime +' . $this->argument('days') . ' -delete');
    }
}

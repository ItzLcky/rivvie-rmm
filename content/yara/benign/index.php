<?php
// An ordinary page: reads a parameter, escapes it, runs a fixed command.
$q = $_GET['q'] ?? '';
echo '<p>' . htmlspecialchars($q, ENT_QUOTES) . '</p>';
echo '<pre>' . htmlspecialchars(shell_exec('uptime')) . '</pre>';

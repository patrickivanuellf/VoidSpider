<?php
$name = htmlspecialchars($_POST['name'] ?? '', ENT_QUOTES);
echo "Halo, $name!";

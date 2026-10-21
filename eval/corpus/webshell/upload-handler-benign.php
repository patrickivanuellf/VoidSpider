<?php
$target = __DIR__ . '/uploads/' . basename($_FILES['file']['name']);
if (move_uploaded_file($_FILES['file']['tmp_name'], $target)) {
    echo "ok";
}

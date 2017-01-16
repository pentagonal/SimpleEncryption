<?php
/**
 * Working Example Encryption
 */
require_once __DIR__ . '/../vendor/autoload.php';
/**
 * Default Empty Result
 * @var string
 */
?>
<!DOCTYPE html>
<html>
<head>
  <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
  <title>Pentagonal Simple Encryption Example</title>
  <style type="text/css">
  *,
  *:after,
  *:before {
    box-sizing: border-box;
    -webkit-box-sizing: border-box;
  }
  body {
    background: #fff;
    color: #555;
    font-size: 14px;
    font-family: "Helvetica", arial, sans-serif;
    line-height: normal;
    vertical-align: baseline;
    background: #f1f1f1;
  }
  #content {
    max-width: 90%;
    margin: 0 auto;
    width: 500px;
  }
  input[type=text],
  textarea {
    display: inline-block;
    width: 100%;
    height: 34px;
    padding: 6px 12px;
    font-size: 14px;
    line-height: 1.42857143;
    color: #777;
    background-color: #fff;
    background-image: none;
    border: 1px solid #ddd;
    border-radius: 2px;
    max-width: 100%;
  }
  textarea {
    background-color: #f7f7f7;
    height: 100px;
  }
  input:-webkit-autofill, textarea:-webkit-autofill {
   -webkit-box-shadow: 0 0 0 1000px white inset;
    color: #777 !important;
  }
  input:focus:-webkit-autofill, textarea:focus:-webkit-autofill {
   -webkit-box-shadow: 0 0 0 1000px white inset;
    color: #555 !important;
  }
  label {
    font-size: 12px;
    display: inline-block;
    line-height: 1;
    margin-bottom: 1em;
  }
  button {
    display: inline-block;
    color: #777;
    background-color: #fff;
    padding: 4px 19px;
    margin-bottom: 1.5px;
    font-size: 13.5px;
    font-weight: normal;
    line-height: 1.42857143;
    text-align: center;
    white-space: nowrap;
    vertical-align: middle;
    cursor: pointer;
    -webkit-user-select: none;
       -moz-user-select: none;
        -ms-user-select: none;
            user-select: none;
    background-image: none;
    border: 1px solid #cdcdcd;
    box-shadow: 0px 1.5px .1px #bfbfbf;
    -webkit-box-shadow: 0px 1.5px 0px #bfbfbf;
    border-radius: 2px;
  }
  button:hover,
  button:focus {
    color: #666;
    text-decoration: none;
  }
  button:active {
    background-image: none;
    outline: 0;
    -webkit-box-shadow: inset -1px 1px 2px rgba(0, 0, 0, .1);
          box-shadow: inset -1px 1px 2px rgba(0, 0, 0, .1);
  }
  .info {
    padding: 10px;
    background: #f3f3f3;
    border: 1px solid #ddd;
    margin: .3em 0;
    display: block;
  }
  </style>
</head>
<body>
  <div class="wrap">
    <div id="content" role="main">
      <h1>Encryption Example</h1>
      <div class="info">
        mCrypt is : <?php echo extension_loaded('mcrypt') ? '&radic; enabled' : '&times; disabled';?>
      </div>
      <form method="POST" action="">
        <p>
          <label for="value">Encryption Value</label><br/>
          <input type="text" name="value" id="value" value="<?php echo ! empty($_POST['value']) ? $_POST['value'] : '';?>" placeholder="insert encryption value ..." required>
        </p>
        <p>
          <label for="key">Encryption Key</label><br/>
          <input type="text" name="key" id="key" value="<?php echo ! empty($_POST['key']) ? $_POST['key'] : '';?>" placeholder="insert encryption key ...">
        </p>
        <p>
<?php
          $method  = !empty($_POST['method']) ? $_POST['method'] : 'encrypt';
?>
          <label><input type="radio" name="method" value="encrypt"<?php echo $method == 'encrypt' ? 'checked' : '';?>>Encrypt</label>
          <label><input type="radio" name="method" value="decrypt"<?php echo $method == 'decrypt' ? 'checked' : '';?>>Decrypt</label>
        </p>
        <p><button type="submit">Submit</button></p>
      </form>
      <div id="result">
<?php
        if (!empty($_POST['method']) && in_array($_POST['method'], array('decrypt', 'encrypt')) && !empty($_POST['value'])) {
          $value = $_POST['value'];
          $key   = empty($_POST['key']) ? null : $_POST['key'];
          if ($_POST['method'] == 'decrypt') {
              $result = \Pentagonal\SimpleEncryption\Encryption::decrypt($value, $key);
?>
          <p>Here the result decryption :<?php echo ! $result ? '(invalid value or key)' : '';?></p>
          <textarea readonly><?php echo $result;?></textarea>
<?php
          } else {
?>
          <p>Here the result encryption :</p>
<?php
if (extension_loaded('mcrypt')) {
          /**
           * Doing mCrypt Encryption
           */
          $result = \Pentagonal\SimpleEncryption\Encryption::encrypt($value, $key);
?>
          <label for="encryptionmcrypt">Encryption Using mcrypt</label><br/>
          <textarea id="encryptionmcrypt" readonly><?php echo $result;?></textarea>
<?php
}
          /**
           * Doing alternative Encryption
           */
          $result = \Pentagonal\SimpleEncryption\Encryption::altEncrypt($value, $key);
?>
          <label for="encryptionalt">Encryption Using Alternative Encryption</label><br/>
          <textarea id="encryptionalt" readonly><?php echo $result;?></textarea>
<?php
          }
      }
?>
      </div>
    </div>
  </div>
</body>
</html>
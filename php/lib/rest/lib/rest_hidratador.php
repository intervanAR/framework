<?php

namespace rest\lib;


class rest_hidratador {


	/**
	 * Formatea un recordset de acuerdo a una especificacion seg�n la clase /lib/modelable
	 */
	public static function hidratar($spec, $fuente)
	{
		$return = array();
		foreach ($fuente as $fila){
			$return[] = self::aplicar_spec_fila($spec, $fila);
		}
		return self::aplicar_group_by($spec, $return);

	}

	/**
	 * Formatea una fila de acuerdo a una especificacion seg�n la clase /lib/modelable
	 */
	public static function hidratar_fila($spec, $fuente,  $merges = array())
	{
		$h = self::hidratar($spec, array($fuente), $merges);
		return $h[0];
	}

	/**
	 * Revierte un objeto hidratado - Deber�a ser el formato que maneja el usuario, por lo tanto
	 * puede usarse para mapear el input del usuario al formato del modelo.
	 * @param $data array la fila para deshidratar
	 * @param $spec_hidratar
	 * @param array $nueva_fila Se utiliza para poder llamar la funcion recursivamente.
	 *                          Posiblemente no se necesite utilizarla en la llamada inicial
	 * @return array la fila deshidratado
	 */
	static function deshidratar_fila($data, $spec_hidratar, &$nueva_fila = array())
	{

		foreach ($spec_hidratar as $key => $campo) {
			if(!is_array($campo)){ //si no proveen todos los campos no los incluyo.
				if(isset($data[(string)$campo]))
					$nueva_fila[(string)$campo] = $data[(string)$campo]; // 2 => 'campo'
				continue;
			}
			if(!isset($data[$key])) continue;

			if(isset($campo['_mapeo'])){// "nombre" => array('_mapeo' => "otro nombre",
				$nueva_fila[$campo['_mapeo']] = $data[$key];
				continue;
			}
			if(isset($campo['_compuesto'])){
				//pongo en la misma fila, las columnas del compuesto
				self::deshidratar_fila($data, $spec_hidratar['_compuesto'], $nueva_fila);
				continue;
			}
			//pasa derecho
			$nueva_fila[$key] = $data[$key];
		}

		return $nueva_fila;
	}

	protected static function aplicar_spec_fila($spec, $fila)
	{
		$nueva_fila = array();
		foreach ($spec as $key => $campo) {
			if(!is_array($campo) && !is_numeric($key)){
				throw new rest_error_interno("Hidratador: no se acepta el formato para la columna $key. Debe ser un arreglo o solo el nombre de la columna");
			}

			if(is_array($campo) && isset($campo['_mapeo'])){// "nombre" => array('_mapeo' => "otro nombre",
				$nueva_fila[$key] = $fila[$campo['_mapeo']];
				continue;
			}
			if(is_array($campo) && isset($campo['_compuesto'])){
				$nuevo_objeto = self::aplicar_spec_fila($campo['_compuesto'], $fila);
				$nueva_fila[$key] = $nuevo_objeto;
				continue;
			}
			//pasa como viene
			if(is_array($campo)){
				$nueva_fila[$key] = $fila[$key]; // 'key' => array()..
			}else {
				$nueva_fila[$campo] = $fila[$campo]; // 2 => 'campo'
			}

		}
		return $nueva_fila;
	}


	protected static function aplicar_group_by($spec, $fuente)
	{

		$grupos = array();
		$id_fila = null;
		if(isset($spec)){ //veo si tiene grupos
			foreach ($spec as $columna => $fila_spec) {
				if(is_array($fila_spec) && isset($fila_spec['_agrupado'])){
					$grupos[$columna] = 1;
				}
				if(is_array($fila_spec) && isset($fila_spec['_id'])){
					$id_fila = $fila_spec['_id'];
				}
			}
		}
		if(empty($grupos)){
			return $fuente;
		}
		if(!isset($id_fila)){
			throw new rest_error_interno("Se debe especificar una columna '_id' para poder usar '_agrupado'");
		}


		$return = array();
		foreach ($fuente as $fila){
			foreach ($grupos as $columna => $agrupado_por){
				if(isset($return[$id_fila])){ //ya existe, solo mergeo los grupos
					$return[$id_fila][$columna][] = $fila[$columna];
				}else{
					$fila[$columna] = array($fila[$columna]); //pongo el grupo en un arreglo
					$return[$id_fila] = $fila;
				}
			}
		}
		return array_values($return);
	}
}
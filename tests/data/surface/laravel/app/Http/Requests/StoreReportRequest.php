<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class StoreReportRequest extends FormRequest
{
    public function authorize()
    {
        return $this->user()->can('create-report');
    }

    public function rules()
    {
        return [
            'title' => 'required|string',
            'body' => 'required',
        ];
    }
}
